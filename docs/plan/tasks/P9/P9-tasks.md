# P9 — Windows alerts, added beside the Linux path (Director, 29/09/2026, DEC-149)

> Chủ đồ án đọc §0–§2 và §5; phiên Coder đọc toàn bộ tệp và làm đúng một card (§3 hoặc §4).
>
> - **Chỉ thêm, không sửa.** Đường xử lý alert Linux phải giữ nguyên từng byte.
> - **Không merge trước khi lần chạy P7-T08 cuối cùng xong.**
> - **Phía Windows là "đã làm, chưa đo":** tập vàng `gold_v1` không có dữ liệu Windows.

## 0 · Why, and the Owner's decisions (verbatim, 28/09, session G)

The Owner's three decisions, verbatim:
- (a) *"hãy dùng song song linux và windows. đừng bỏ job hiện tại. Phía windows thì thêm chứ không sửa cái có sẵn"*
- (b) *"trên windows thì để brute force attemp hoặc login brute force dựa vào theo chuẩn tatic mitre"*

  This means a **new** category for Windows credential attacks, named after MITRE ATT&CK **T1110 "Brute Force"**. `ssh_brute_force` keeps its name and its meaning. This file uses **`brute_force`** as the category name. The Owner confirms the name before §4 is dispatched; a rename is a one-line change in §4 before anyone starts.
- (c) *"Tiến hành thêm phía alert windows trong hôm nay đi. Tôi sẽ làm sau khi làm xong công việc cần làm hôm nay"*

Working assumption, pending the Owner's confirmation: Windows status codes and Logon Types go into playbook text only. They add **no** new fact to `backend/app/kb/lookup.py`, and none to the decision-table contract that the ten tables were signed against.

How a Windows alert flows today, step by step against the code, is in the Director's 28/09 answer to the Owner (DEC-149 item 2). In short:
- The puller, dedup, enrichment code, ① and the gate need no change.
- Three places need additions:
  - the parser, which ignores `data.win.*`;
  - the category resolver, which would file Windows T1110 alerts under `ssh_brute_force`;
  - a playbook and a decision-table skeleton for the new category.
- The inventory and identities files need Windows rows (configuration, the Owner's).

## 1 · Guardrails (every card)

1. **Where.** Work on branch `feature/windows-alerts` in worktree `.claude/worktrees/windows-alerts`, both cut from the director branch. Do not touch:
   - the primary checkout: `backend/app`, `kb/` and `eval/` there are live-mounted into the running containers;
   - `main` or the director branch;
   - any container;
   - the database, beyond read-only `SELECT`s.
2. **When it lands.** The Director merges only **after the last P7-T08 run** and after review. Only then does the Owner fast-forward `main` and run `docker compose restart app worker`. Until then nothing here reaches the measured system (DEC-145 item 5, DEC-148).
3. **Additive only.** These stay byte-identical:
   - every Linux alert's parsed `Alert`;
   - every Linux alert's category;
   - the ten signed tables (tree `48329d72fd1f7611c006cb44748317df2d2d4faf`).

   Edit **no** existing test except the pins §4 names, each extended rather than weakened.
4. **No synthetic data outside tests.** Test fixtures may be modelled on Wazuh's documented `windows_eventchannel` shape until real alerts exist. Each such fixture carries `"_fixture": "synthetic"`, and none is ever loaded into a database or used by `eval/`. Before merge, at least one **real** alert per event type the card claims to handle comes from the Owner's Windows agent. Read it from `intake.raw_text`, read-only.
5. **The suite, known green (DEC-144 item 4).**
   - `make lint PY=$PY`: 0.
   - `make test PY=$PY`: 0 failed.
   - `make test-db PY=$PY`: all pass.

   Run test-db with no other pytest running (`pgrep -fc '[p]ytest'` → 0) and never print `ps` arguments. A worktree needs a temporary `.env` symlink to the primary checkout's `.env` for test-db; remove it right after.
6. **No attack commands.** A card never writes or runs one. Test events are the Owner's (§5).

## 2 · Owner prerequisites (P9-O1, not a Coder card)

1. **A Windows machine with a Wazuh agent enrolled to the manager on ATTT-M1** (a VM is fine). Collect:
   - Security, with audit policy for Logon/Logoff, Account Lockout and Credential Validation, so that 4624/4625/4648/4672/4740/4768/4771/4776 are logged;
   - Sysmon event IDs 1/3/11/13/22, if Sysmon is installed. Without Sysmon, `c2_beacon` and `data_exfiltration` have almost no Windows signal;
   - Microsoft-Windows-Windows Defender/Operational (1116/1117);
   - optionally PowerShell 4104.
2. **`conf/inventory.yaml`:** the Windows host, with a `criticality` from `high|medium|low|unknown` (the content is the Owner's, DEC-066). **`conf/identities.yaml`:** the Windows accounts that are privileged (Administrator, members of Administrators/Domain Admins). Both files are git-ignored and written by the Owner. Without them, asset and identity resolve to `unknown`.
3. **Check:** in the Wazuh dashboard, alerts from the new agent appear with `decoder.name = windows_eventchannel`.

## 3 · P9-T01 — `ingest/wazuh_parser.py` reads `data.win.*` (Coder, ≈ 2 h)

**Today.** `parse_wazuh_alert` takes these fields only from the Linux shape:
- `srcip`/`dstip`/ports from `data.srcip`/`data.dstip`/`data.srcport`/`data.dstport`, and the user from `data.dstuser`/`data.srcuser` (`:175-180`);
- `raw_log` from `full_log` (`:197-198`).

A Windows eventchannel alert keeps these under `data.win.eventdata`/`data.win.system`, and usually has no `full_log`. So today a Windows alert has an empty IP, no user and an empty `raw_log`.

**Task.** Add a pure helper, e.g. `_windows_fields(data) -> …`. Use its values **only when the Linux field is empty and `data.win` is a mapping**:
- **srcip:** `eventdata.ipAddress` (4624/4625/4648/4776), else `eventdata.sourceIp` (Sysmon 3). **dstip:** `eventdata.destinationIp`.
- **ports:** `eventdata.ipPort` or `eventdata.sourcePort`; `eventdata.destinationPort`.
- **user:** `eventdata.targetUserName`, else `eventdata.subjectUserName`, else the account part of Sysmon's `eventdata.user` (`DOMAIN\name` → `name`).
- **Treat as empty:** `-`, `""`, `127.0.0.1`, `::1`, `0.0.0.0`, and machine accounts ending in `$`.
- **`raw_log` when `full_log` is empty:** `data.win.system.message` if non-empty, else `json.dumps(data["win"], sort_keys=True, ensure_ascii=False)`, through the existing `_truncate_raw_log`.
- `eventID`, `status`, `subStatus`, `failureCode`, `logonType`, `image`, `targetFilename` and `queryName` are **not** new `Alert` fields. They stay in `raw_payload` and reach ① through `raw_log`.

**Tests.** A new file, `backend/tests/test_wazuh_parser_windows.py`:
1. **Linux unchanged.** For every Linux document the existing parser tests use, the parsed `Alert` equals a snapshot produced by the **base commit's** parser. That covers `event_bucket_hash` and hence the dedup key. Produce the snapshots with a script run on the base commit, and commit them as test data.
2. **One case per event type:** 4625 (network logon failure with `ipAddress`), 4624 logon type 10, 4740, Sysmon 1/3/11/22, Defender 1116. Each checks the extracted fields, the empty-value filters and the `raw_log` fallback.
3. **No double reading:** a document with both `data.srcip` and `data.win.eventdata.ipAddress` keeps `data.srcip`.

**Acceptance.**
- §1 item 5's suite.
- `git diff --stat <base> -- backend/tests` lists only new files.
- At least one real fixture per event type before merge (§1 item 4).

## 4 · P9-T02 — the `brute_force` category, resolver and knowledge base (Coder, ≈ 3 h)

1. **`ingest/category.py`.** Add a Windows tier consulted **before tier 1, only when `decoder` contains `windows_eventchannel`**: `WINDOWS_TECHNIQUE_TO_CATEGORY`.
   - `T1110`, `T1110.001`, `T1110.003` → `brute_force`.
   - Windows-only MITRE ids with no key in the shared table:
     - `T1490`, `T1485` → `ransomware`;
     - `T1071.001`, `T1573` → `c2_beacon`;
     - `T1048`, `T1567` → `data_exfiltration`;
     - `T1059.001` → `malware`.

   If nothing matches, fall through to the existing five tiers unchanged: T1078 → `suspicious_login`, T1486 → `ransomware`, and so on. The shared tables are **not** edited, so a Linux alert cannot change category by construction.

   Insert `brute_force` into `PRIORITY` directly after `ssh_brute_force`. Bump `MAPPING_VERSION` `v3.2` → `v3.3`.
2. **Two test pins are extended, not weakened.**
   - `test_category.py::test_mapping_version_is_pinned_to_a_hash_of_the_four_tables`: hash the Windows table as well and pin `v3.3`.
   - `test_kb_lookup.py`: `CATEGORIES` now includes `brute_force`. Pin the **ten signed categories explicitly** in `test_tables_are_reviewed`, with `SIGNED_BY`/`SIGNED_AT` unchanged. Add `test_brute_force_table_is_unreviewed`.

   No other existing test is edited.
3. **`kb/playbooks/brute_force.md`.** A draft playbook in the style of `ssh_brute_force.md`:
   - its header states *"agent-drafted 29/09 (P9-T02), not reviewed"*;
   - it covers 4625 NTSTATUS `0xC000006A`/`0xC0000064`/`0xC0000234`, Kerberos 4771 `0x18`/`0x6`/`0x12`, 4740, logon types, and spraying (many accounts, one source) vs brute force (one account, many tries);
   - it stays under the 3,000-token test.

   **`kb/decision_tables/brute_force.yaml`.** A skeleton with `reviewed_by: null`, `reviewed_at: null`, and rules over the existing facts only. `check_consistency` returns `[]`. While unsigned, gate step 4 answers `table_unreviewed`, so ① never auto-closes a `brute_force` alert. That is intended until the Owner and the advisor sign it.
4. **The five shared playbooks** (`suspicious_login`, `malware`, `ransomware`, `c2_beacon`, `data_exfiltration`).
   - Add a short "Windows" subsection to each, headed *"(added 29/09, P9-T02, not reviewed)"*:
     - `suspicious_login`: 4624 after 4625 runs, RDP type 10, 4648, 4672;
     - `malware`: Defender 1116/1117, and Sysmon 1 from `%TEMP%`/`AppData` or `powershell -enc`;
     - `ransomware`: `vssadmin`/`wbadmin`/`bcdedit` via Sysmon 1, and mass Sysmon 11 writes;
     - `c2_beacon`: periodic Sysmon 3, and unusual Sysmon 22;
     - `data_exfiltration`: `rclone`/`curl -T`/`certutil`/archivers via Sysmon 1/11.
   - The signed **tables** are not touched.
   - `c2_beacon` and `data_exfiltration` state plainly that without a network IDS the Windows signal is weak.
5. **Read-only proof that Linux is unchanged:**
   - recompute `resolve(mitre_ids, rule_groups, decoder, dst_port)` for every `alerts` row whose `decoder` does not contain `windows`, from the stored columns, with the new code;
   - compare each result to the stored `category`;
   - it must report `0` differences. Paste the count in the report.

**Acceptance.** §1 item 5's suite, the two extended pins, and item 5's `0`.

## 5 · After P7-T08: merge and first real event

1. The Director reviews P9-T01 and P9-T02 (`.review.md`) and merges them into the director branch after the last P7-T08 run. The whole suite runs on the merged tree.
2. The Owner:
   - fast-forwards `main` and runs `docker compose restart app worker` (a code-only change, so `restart` is enough);
   - then types **one wrong password by hand** at the Windows VM's logon screen.
3. **Check, read-only.** The alert arrives with:
   - a non-empty `raw_log`;
   - `alert_user` set;
   - a category of `brute_force` (rule 60122 via the Windows group tier, `024beda`; the 9 real 60122 rows confirm it).

   It is triaged, and the verdict is not `false_positive` for `brute_force`, because that table is unsigned.
4. `docs/limitations.md` gains one line at P8-T06: *"Windows alerts are parsed, categorised and triaged (P9), but no Windows data is in gold_v1: implemented, not measured."* Measuring it needs a Windows lab, a `gold_v2` and a signing of `brute_force.yaml`.
5. **`docs/results/` is not re-rendered after the merge.** `report.py` enumerates `PRIORITY`, and the committed P7 tables are the measured ones.
