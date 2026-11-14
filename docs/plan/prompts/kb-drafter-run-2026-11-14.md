# KB Drafter — draft the eight playbooks and decision tables of the v3.5 categories

**Invocation (the Owner pastes this, nothing else — session name `kb-drafter-v35`):**

```
Read docs/plan/prompts/kb-drafter-run-2026-11-14.md and act as the KB Drafter. Start with §0.
```

You draft content that two humans (the Owner and the advisor) will review, amend and sign. You are not
one of them. This is a **card-free acceptance contract** (DEC-078 precedent, as the 19/09 run): §8 is
what you must prove. Written by the Director at the Owner's instruction, 14/11 (DEC-216).

## 0 · Why this run exists — read it, it decides where the effort goes

Category mapping v3.5 (`backend/app/ingest/category.py`, DEC-216) added **tier 6**: the Owner's MITRE
ATT&CK technique map, consulted only when every older tier found nothing. On the trial's 7,559 stored
alerts it files 3,592 of the 4,384 `unknown` ones and changes **no** alert that already had a
category. 1,631 of them land in eight **new** categories that have no playbook and no decision table:

`impact` · `collection` · `lateral_movement` · `persistence` · `defense_evasion` · `execution` ·
`initial_access` · `resource_development`

With no playbook, ① is told "no playbook for this alert type" and proposes `false_positive` with no
reasons, and gate step 3 holds every one of them as `needs_review` (DEC-215, T1). R5 — *a category with
no playbook may never be produced* — is red in six tests until you finish (§8 item 1). Your job: one
playbook and one unsigned decision table per category, from the evidence in §3.

## 1 · Read first, in this order

1. `backend/app/kb/lookup.py` — the whole file. It is the contract: `_VOCAB` (the four categorical
   facts and their exact values), `_INT_CONDITION_KEYS` (`occurrence_lt/gte`, `rule_level_lt/gte`),
   `_YAML_ACTION` (**`then:` may be `false_positive`, `needs_review` or `escalate`; `true_positive` is
   refused** — `escalate` loads as ①'s `true_positive`), `_RULE_ID_RE`, `_TITLE_TOKEN_RE`,
   `get_decision_table()` (the `category` must equal the file stem; `playbook` must equal the second
   back-ticked token of the playbook's first line), `fact_grid()`, `check_consistency()`,
   `apply_table()` — read which rule wins before you write one; `severity` is derived from
   `rule_level` (DEC-053 bands), never free.
2. `backend/app/ingest/category.py` — the module docstring, `PRIORITY` and
   `EXTENDED_TECHNIQUE_TO_CATEGORY` (tier 6): which technique ids reach your eight categories.
3. `kb/playbooks/malware.md` (a signed playbook: the seven-section shape) and
   `kb/playbooks/credential_access.md` + `kb/decision_tables/credential_access.yaml` (the newest
   **unsigned, agent-drafted** pair: banner, header comment, evidence lines, the reasoned choice of
   *no* `false_positive` rule). `kb/decision_tables/malware.yaml` `mal-1` is the signed
   `false_positive` pattern.
4. `docs/plan/DECISIONS.md` — **DEC-034** (asset weights; `high` is a hard block), **DEC-053**
   (severity bands), **DEC-058** (unlisted assets pin `needs_review`), **DEC-145** (the 28/09 signing),
   **DEC-208** (on the trial the context comes from SOAR's `enrichment` block; `ENRICHMENT_ENABLED` is
   off, so `ioc_reputation` is usually `skipped`), **DEC-213** (`escalate` → `true_positive`),
   **DEC-215** (no playbook → FP with empty reasons), **DEC-216** (v3.5, this run).
5. `docs/plan/prompts/kb-drafter-run-2026-09-19.md` §2–§3 — the evidence-line and rule-drafting rules
   of the first run; they hold here unless this file says otherwise.
6. `backend/tests/test_kb_lookup.py`, `backend/tests/test_category.py` (R5 block),
   `backend/tests/test_soar_occurrence.py` (`test_there_are_nine_occurrence_lt_rules_…`) — the tests
   that will judge you.

## 2 · Names you must use

| Category | Playbook name | Rule-id prefix | Vietnamese label (already in `frontend/src/strings.ts`) |
|---|---|---|---|
| `impact` | `impact_v1` | `imp` | Phá hoại, gây gián đoạn |
| `collection` | `collection_v1` | `col` | Thu thập dữ liệu |
| `lateral_movement` | `lateral_movement_v1` | `lat` | Di chuyển ngang |
| `persistence` | `persistence_v1` | `per` | Duy trì truy cập |
| `defense_evasion` | `defense_evasion_v1` | `dfe` | Né tránh phòng thủ |
| `execution` | `execution_v1` | `exe` | Thực thi mã |
| `initial_access` | `initial_access_v1` | `ina` | Truy cập ban đầu |
| `resource_development` | `resource_development_v1` | `rsd` | Chuẩn bị hạ tầng tấn công |

The prefixes collide with none of the twelve existing ones (`bf c2b cra dex mal pol pre ran rec sbf sul web`).

## 3 · Evidence — the Wazuh rules v3.5 files into each category (trial DB, 14/11)

Computed by the Director with the v3.5 resolver over every stored trial alert (no host, user or address
included). Almost all of them sit in `queued_tier1` (no analyst verdict yet), so these are **what
fires**, not what is true.

| Category | Alerts | Rule | Level | MITRE | Description | Count |
|---|---|---|---|---|---|---|
| `impact` | 41 | 110229 | 3 | T1531 | User Logoff Event | 20 |
|  |  | 112524 | 5 | T1489 | Process Terminated Via Taskkill | 15 |
|  |  | 751 | 5 | T1070.004,T1485,T1112 | Registry Value Entry Deleted. | 2 |
|  |  | 597 | 5 | T1070.004,T1485,T1112 | Registry Key Entry Deleted. | 2 |
|  |  | 60778 | 5 | T1489 | The shell stopped unexpectedly. | 2 |
| `collection` | 15 | 110903 | 8 | T1114.001 | Powershell Local Email Collection | 13 |
|  |  | 91820 | 4 | T1083,T1119 | Powershell script recursively collected files from a filesystem search | 2 |
| `lateral_movement` | 17 | 92217 | 6 | T1570 | Executable dropped in Windows root folder | 10 |
|  |  | 110814 | 8 | T1021.006 | Enable Windows Remote Management | 3 |
|  |  | 110243 | 8 | T1550.002 | NTLMv1 Logon Between Client and Server | 2 |
|  |  | 92650 | 12 | T1021.002,T1569.002 | New Windows Service Created to start from windows root path | 2 |
| `persistence` | 1,119 | 112438 | 5 | T1197 | BITS Client BitsProxy DLL Loaded By Uncommon Process | 496 |
|  |  | 112533 | 5 | T1053.005 | Scheduled Task Created - Registry | 201 |
|  |  | 92154 | 4 | T1053.005 | Process loaded taskschd.dll module | 124 |
|  |  | 111810 | 5 | T1053.005 | Scheduled Task Creation Via Schtasks.EXE | 56 |
|  |  | 111828 | 12 | T1053.005 | Suspicious Command Patterns In Scheduled Task Creation | 56 |
|  |  | 112430 | 5 | T1053.005 | Scheduled Task Created - FileCreation | 50 |
|  |  | 110798 | 8 | T1053.005 | Powershell Create Scheduled Task | 41 |
|  |  | 110437 | 12 | T1574.001 | HackTool - Powerup Write Hijack DLL | 22 |
|  |  | +11 more rules |  |  |  | 73 |
| `defense_evasion` | 370 | 110665 | 8 | T1220 | WMIC Loading Scripting Libraries | 152 |
|  |  | 112519 | 8 | T1222.001 | File or Folder Permissions Modifications | 50 |
|  |  | 110753 | 3 | T1140 | PowerShell Decompress Commands | 49 |
|  |  | 112466 | 5 | T1070.004 | Use Of Remove-Item to Delete File - ScriptBlock | 34 |
|  |  | 110810 | 8 | T1620 | Potential In-Memory Execution Using Reflection.Assembly | 25 |
|  |  | 110915 | 8 | T1036.003 | Suspicious Start-Process PassThru | 22 |
|  |  | 92021 | 3 | T1070.004 | Powershell was used to delete files or directories | 11 |
|  |  | 112520 | 8 | T1564.004 | Use Short Name Path in Command Line | 6 |
|  |  | +6 more rules |  |  |  | 21 |
| `execution` | 0 | — | — | — | no trial alert: WMI/scripting ids already reach `malware` in tiers 1–2; draft from ATT&CK | — |
| `initial_access` | 19 | 110464 | 5 | T1566.001 | Office Macro File Creation | 19 |
| `resource_development` | 50 | 112431 | 5 | T1587.001 | Creation of an Executable by an Executable | 33 |
|  |  | 110256 | 3 | T1584 | Windows Update Error | 17 |

Three things in this table are traps, and each playbook must say so in its §3 or §4:

- **Noise under a serious name.** `110229 User Logoff Event` (T1531, level 3) lands in `impact`;
  `110256 Windows Update Error` (T1584, level 3) lands in `resource_development`. The category comes
  from the rule's MITRE tag, not from what happened. The playbook must tell ① how to recognise the
  routine case.
- **Admin work that looks like persistence.** Scheduled-task and BITS rules (≈ 1,000 alerts) fire on
  software updaters and management agents all day. The playbook must separate a known updater or
  management tool from a task pointing at a user-writable path, an encoded command or a script host.
- **`execution` has no data.** Write it from ATT&CK and the lab's attack chains only, and say in the
  header that it is unmeasured ("implemented, not measured", as `credential_access.yaml` does).

## 4 · The playbook — `kb/playbooks/<category>.md`

- **Line 1, exactly:** ``# Playbook · `<category>` · `<category>_v1` `` (the loader reads the two
  back-ticked tokens; the table's `playbook:` must equal the second).
- **Line 3, the banner:** `> **agent-drafted 14/11 (DEC-216, mapping v3.5), not reviewed** — …`, then
  one `>` paragraph naming the ATT&CK tactic and the techniques of §3 that reach it.
- **Sections, the signed shape** (`malware.md`): `## 1 · Ba câu phân định` · `## 2 · Kiểm gì — cụ thể`
  · `## 3 · Nghiêng về FALSE POSITIVE khi` · `## 4 · Nghiêng về THẬT khi` ·
  `## 5 · Ngữ cảnh làm đổi kết luận` · `## 6 · Chưa kết luận được thì cần thêm` · `## 7 · Windows`
  (Sysmon / Security event ids and the `raw_log` fields to read: `Image`, `CommandLine`,
  `ParentImage`, `TargetObject`, `TaskName`…).
- **Vietnamese**, the register of the existing playbooks; ATT&CK ids and field names stay as they are.
- **Under 3,000 tokens** (`test_largest_playbook_under_3000_tokens`).
- Every claim must be checkable in what ① actually receives: `raw_log`, the rule description, the
  correlation samples, `context`, `siem_context`. Do not tell ① to look at something it cannot see
  (a process tree it was not given, a ticketing system).
- §5 must carry the hard context rules every playbook carries: `asset_criticality = high` or `unknown`
  (unlisted) → treat as an incident; a privileged identity → assume credentials are exposed.

## 5 · The decision table — `kb/decision_tables/<category>.yaml`

- **Header comment** in the `credential_access.yaml` shape: SKELETON, UNSIGNED; DRAFT 14/11/2026 —
  agent-drafted (DEC-216, mapping v3.5), not reviewed; the techniques; what the facts cannot see and is
  therefore left to the playbook; whether a fold was measured (it was not: no gold alert carries these
  categories — say "implemented, not measured").
- `category: <category>` · `playbook: <category>_v1` · **`reviewed_by: null` · `reviewed_at: null`**.
- **3 to 6 rules**, ids `<prefix>-<n>`, unique, in the order `apply_table` evaluates them. Conditions
  use only `_VOCAB` keys/values and `_INT_CONDITION_KEYS`. One `# evidence:` comment line **above every
  rule**, citing the playbook line and the §3 rule ids/counts (`(no trial alert — ATT&CK only)` where
  true). **A rule without an evidence line is a defect.**
- Keep the two rules every table has: `{ioc_reputation: [malicious, suspicious]} → escalate` and a
  `rule_level_gte: 12 → escalate` band (check §3: some categories have level-12 rules).
- **`false_positive` — at most one rule, and only on the signed structural pattern** (`mal-1`):
  `severity: [low, medium]`, `ioc_reputation: [not_found, clean]`, `asset_criticality: [low, medium]`,
  `identity_privileged: ["false"]`, `occurrence_lt: 50`. Never on a `high` or `unknown` asset, a
  privileged or unknown identity, `critical`, or a bad IoC — gate step 4 refuses those anyway, and a
  table that says otherwise is wrong on its face. If the facts cannot separate the routine case from the
  attack (the noise of §3 is separated by *what* ran, which is not a fact), write **no** FP rule and say
  why in the header, as `credential_access.yaml` does. `lateral_movement` and `impact` most likely
  deserve none.
- **If you write an FP rule with `occurrence_lt`**, `test_soar_occurrence.py`
  `test_there_are_nine_occurrence_lt_rules_and_every_one_is_a_false_positive_of_50` pins the full list
  of such rules: change its count and add your ids to its sorted list, in the same commit. That pin is
  the **only** test you may edit, and only that way (value 50 and action `false_positive` stay asserted).
- `check_consistency()` over the 2,520-point grid must return `[]` for every table.
- `identity_privileged` values are the **strings** `"true"`/`"false"`/`"unknown"`, quoted.

## 6 · Hard rules

- Edit only `kb/playbooks/<the eight>.md`, `kb/decision_tables/<the eight>.yaml`, the one test pin of
  §5, and the two `docs/plan/kb-*-2026-11-14.md` files of §7. Never `category.py`, `lookup.py`,
  the twelve existing playbooks/tables, other tests, or anything else under `backend/` or `frontend/`.
- **Never fill `reviewed_by` / `reviewed_at`.** Until the sitting signs, the gate treats each table as
  absent (`decision_table_unreviewed:<category>`) and step 4 answers `table_unreviewed`: nothing you
  write can auto-close an alert.
- No LLM calls. No database access (the evidence is §3). No network. No secret, host name, user name or
  address in any file — the repository is public.
- Work on a branch `kb/v35-playbooks` cut from `director/trial-category-v35`; one commit per category
  (its playbook + table), one for the sheet and the report. Never `main`, never a push.

## 7 · Deliverables

1. The eight `kb/playbooks/*.md` and eight `kb/decision_tables/*.yaml` of §2.
2. `docs/plan/kb-review-sheet-2026-11-14.md` — the document the sitting works from: one section per
   category (the playbook's §3/§4 in two lines, the rules with their evidence, the question you could not
   settle, a `[ ] signed` line), then the three traps of §3 and how each playbook handles them, then
   the exact edit that turns a signature into the file (`reviewed_by: "<name>"`,
   `reviewed_at: "<ISO date>"`) and the test that proves it.
3. `docs/plan/kb-draft-report-2026-11-14.md` — what you read, what each rule came from, what you could
   not determine, in that order.

## 8 · Acceptance — every line is a command you run and paste

`$PY` is the project venv's interpreter (`.venv/bin/python` of the primary checkout; the host's
`python3` lacks the dependencies).

1. `$PY -m pytest -c backend/pyproject.toml -m "not db" backend/tests/test_category.py backend/tests/test_category_windows.py backend/tests/test_kb_lookup.py backend/tests/test_soar_occurrence.py backend/tests/test_rag_tags.py backend/tests/test_builder.py -q`
   → **0 failed**. Before you start, exactly six are red (all R5 / playbook-count):
   `test_r5_every_mapped_value_has_a_real_playbook`, `test_priority_table_is_covered_by_playbooks_plus_unknown`,
   `test_ten_playbooks_exist_on_disk_matching_r5s_premise`, `test_every_category_has_one_playbook_and_one_table`,
   `test_skeletons_are_consistent`, `test_largest_playbook_under_3000_tokens`. Paste the before and the after.
2. `grep -c "reviewed_by: null" kb/decision_tables/{impact,collection,lateral_movement,persistence,defense_evasion,execution,initial_access,resource_development}.yaml`
   → eight lines, each `:1`.
3. `for f in kb/decision_tables/{impact,collection,lateral_movement,persistence,defense_evasion,execution,initial_access,resource_development}.yaml; do printf "%s %s/%s\n" "$f" "$(grep -c '# evidence:' "$f")" "$(grep -c '^  - id:' "$f")"; done`
   → the two numbers equal on every line, and every rule count in **3..6**.
4. `$PY -c "import sys; sys.path.insert(0,'backend'); from app.kb.lookup import get_decision_table, check_consistency; [print(c, len(get_decision_table(c).rules), check_consistency(get_decision_table(c))) for c in ('impact','collection','lateral_movement','persistence','defense_evasion','execution','initial_access','resource_development')]"`
   → eight lines, each ending in `[]`.
5. **Failing case (DEC-025):** copy one of your tables to a scratch directory, add a rule that
   contradicts an existing one on a shared grid point, run `check_consistency` on it → **non-empty**;
   paste it. A checker that cannot go red proves nothing.
6. `make lint PY=$PY` → exit 0.
7. `git diff director/trial-category-v35...kb/v35-playbooks --stat` → only the sixteen `kb/` files,
   `backend/tests/test_soar_occurrence.py` (only if §5 applied) and the two `docs/plan/kb-*-2026-11-14.md`.
8. `grep -rnE "([0-9]{1,3}\.){3}[0-9]{1,3}|@[a-z0-9-]+\." kb/playbooks/{impact,collection,lateral_movement,persistence,defense_evasion,execution,initial_access,resource_development}.md`
   → nothing (no address, no account).

## 9 · After you — for the Director and the Owner, not for you

- `kb/` is mounted live into the trial (`/srv/kb`): a playbook reaches ① on the next alert, with no
  restart. A table changes nothing until `reviewed_by`/`reviewed_at` are signed.
- Even signed, a `false_positive` survives gate step 4 only if ① cites the rule id in
  `structured_basis.playbook_rule_applied`, and today ① is never shown the table's ids (only the
  verifier is). That is a separate card (the Director's needs_review analysis of 14/11), not yours.
- Alerts stored before v3.5 keep their old category: re-classifying them is a separate, Owner-run step.
