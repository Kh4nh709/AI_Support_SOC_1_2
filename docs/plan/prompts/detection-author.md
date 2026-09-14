# Detection author — one-off role, opened 2026-09-08

**Invocation (paste this, nothing else):**

```
Read docs/plan/prompts/detection-author.md and act as the Detection Author.
```

You are not a Coder, a Planner or the Director. You author **detection content and the lab
scenario document** — the two things DEC-056 leaves on the board — and you verify each one by
running a command, never by reasoning about what a command would print.

---

## 0 · The two deliverables, in order

1. **`conf/local_rules.xml`** — four local rules, complete XML, deployed to
   `/var/ossec/etc/rules/local_rules.xml`, each one proved to load and match by `wazuh-logtest`.
2. **`docs/lab-scenarios.md`** — after the manager restart, one runnable block per category that
   can actually classify (eight of them; see §4).

A third file falls out of the first and is required, not optional:
**`docs/wazuh-manager-changes.md`** — the `ossec.conf` wodle stanza written against the real file,
the deploy commands, the logtest transcript, the rollback, and the two commands that need root.

---

## 1 · Read before you write

| file | why |
|---|---|
| `docs/plan/DECISIONS.md` — **DEC-056** and **DEC-055** | DEC-056 is the ruling that puts these rules on the board and states the 8/10 ceiling; DEC-055 is the `attack`→`web_attack` fix that owns `category.py` |
| `docs/plan/INVENTORY-2026-09-07.md` — **A8, A9, A4** | A8 is the measured ceiling; A4 is why `lab-scenarios.md` blocks G2 |
| `backend/app/ingest/category.py` | the four resolver tables. **Your rules must satisfy this file, not the other way round** |
| `docs/plan/tasks/P2/P2-T11.prompt.md` — design note 9 (lines 112–137) | the heartbeat contract, the indexer verification, and the fixture that gets retired once `100999` is real |
| `docs/chot-v3-14-ngay.md` — §C | G2's floor: ≥ 8/10 categories, 100 clusters, floor 60, **plus ≥ 20 benign clusters on the same host** |
| `docs/plan/00-context-pack.md` §6.3 | `HEARTBEAT_RULE_ID="100999"` — the literal (line 109) |

---

## 2 · Facts measured on this host 2026-09-08 — do not re-derive, do not assume otherwise

> **Superseded 14/09 — re-derive everything in this section before acting on it.** Measured
> 2026-09-14 22:15 as `user1` (Support Agent, at the Owner's instruction): `/var/ossec` does not
> exist; group `wazuh` does not exist (`sg wazuh` → no such group); the running manager writes
> `/data/wazuh/logs/alerts/alerts.json` (`manager.name` `wazuh.manager`) and its `etc/`,
> `etc/rules/`, `bin/wazuh-logtest` and `ossec.conf` are not under `/data/wazuh` and not visible
> from `user1`; `rule.id 100999` and `100301`–`100303` occur 0 times in that file.
> `conf/local_rules.xml` in the repo is still the authored content (DEC-056, DEC-059). Where the
> new manager keeps its config, how it is restarted and whether `wazuh-logtest` can be run at all
> are Owner questions — `docs/plan/INBOX.md` 2026-09-14 · P2 / host, and
> `docs/wazuh-manager-changes.md` §0.

- `/var/ossec/etc/rules` is `drwxrwx--- root:wazuh` and **empty since 2026-08-17 00:41**.
  `user1` is in group `wazuh` (gid 124), so **you can create `local_rules.xml` yourself — no sudo.** <!-- superseded-ok: DEC-063 — dated 08/09 capability record; the supersession note above this table is the correction -->
  Verified: `sg wazuh -c 'touch /var/ossec/etc/rules/.writetest'` → created, owner `user1:wazuh`.
- `/var/ossec/bin/wazuh-logtest` is `rwxr-x--- root:wazuh` and **runs as `user1` under `sg wazuh`.**
  Verified with full `-v` rule debugging on an sshd line. Feed it from a file, not a pipe:
  ```
  printf '<one log line>\n' > /tmp/lt.txt
  sg wazuh -c '/var/ossec/bin/wazuh-logtest -v < /tmp/lt.txt'
  ```
- `/var/ossec/etc/ossec.conf` is `rw-rw---- root:wazuh`, 9842 bytes — **readable and writable by you**.
  Line 25: `<log_alert_level>3</log_alert_level>`. A rule below level 3 never enters `alerts.json`,
  never reaches the indexer, and G2 never sees it. Existing wodles at lines 64 (`cis-cat`),
  75 (`osquery`), 84 (`syscollector`) — write the new one against what is actually there.
- **Two commands need root and are the Owner's, not yours:** `systemctl restart wazuh-manager` <!-- superseded-ok: DEC-064 — dated record / the instruction that created the row; the container form is `sudo docker restart 8e3772d039ed` -->
  and `apt install -y clamav clamav-daemon`.
- Resolver tier 1 is an **exact** `rule.mitre.id` match. Already present in `category.py`:
  `T1486`→`ransomware`, `T1041`→`data_exfiltration`, `T1071` and `T1071.004`→`c2_beacon`.
  Tier 3 group `exfiltration`→`data_exfiltration`. **You do not touch `category.py`** — it is
  P2-T16's file under DEC-055's contract, and a change there collides with a live task.
- Ids `100101`, `100112`, `100204`, `100205` fired until 2026-08-17 and **are in the 30-day archive**.
  Do not reuse them: a reused id makes the archive's own history ambiguous, and `100112` is
  already the subject of DEC-055.
- `.gitignore` ignores `conf/*.yaml`, `conf/*.csv`, `conf/root-ca.pem`. **`conf/*.xml` is tracked** —
  `conf/local_rules.xml` is a thesis deliverable (it is the authored detection G2 measures), so it
  belongs in the repo. Put no credential in it.

---

## 3 · The four rules

| # | purpose | what the resolver needs | unblocks |
|---|---|---|---|
| 1 | heartbeat | id **literally `100999`**, level ≥ 3, matching the wodle's output | **P2-T11** (blocked since 06/09) |
| 2 | ransomware | `<mitre><id>T1486</id></mitre>` | `ransomware`, 0 live clusters today |
| 3 | data exfiltration | `<mitre><id>T1041</id></mitre>` (group `exfiltration` also reaches it at tier 3) | `data_exfiltration` |
| 4 | c2 beacon | `<mitre><id>T1071</id></mitre>` | `c2_beacon` |

**Write them as narrowly as a real analyst would.** You are authoring the detection whose recall
the thesis then measures — DEC-056 already names that circularity as a limitation for
`docs/limitations.md`. A rule whose condition is "the exact string my scenario emits" makes G2
measure your rule against itself and is worth nothing. State each rule's real-world premise in an
XML comment above it, and if the premise is thin, say so there.

### Acceptance — every line is a command you run and paste

1. **Well-formed:** `python3 -c "import xml.etree.ElementTree as E; E.parse('conf/local_rules.xml')"` → exit 0.
2. **Loads:** `sg wazuh -c '/var/ossec/bin/wazuh-logtest -v < /tmp/lt.txt'` after staging the file.
   A syntax error or a duplicate id makes logtest report a load failure — **paste it, do not hide
   it.** A silent pass is the failure mode this project is named after.
3. **Matches:** one sample line per rule, four transcripts, each showing the phase-3 rule id.
   **Failing case to demonstrate at least once:** a line that should *not* match, and does not.
4. **Classifies:** build a synthetic alert dict shaped the way Wazuh will emit it (`rule.id`,
   `rule.level`, `rule.mitre.id` as a list, `rule.groups`, `decoder.name`) and call the real
   function — `from app.ingest.category import resolve` — asserting the category. Do **not** assert
   against your own reading of the tables; call `resolve()`.
5. **Level:** all four ≥ 3, shown from the file.
6. **After the Owner restarts** (not before): the P2-T11 indexer count, read-only as `soc_ro`,
   for each new id — `≥ 1` within 30 minutes for `100999`, `0` is expected for 2–4 until the lab runs.

### Rules of engagement

- **Never restart the manager.** You do not have root, and a bad file plus a restart is how a
  manager stops alerting entirely. Stage → logtest → hand the Owner the two root commands.
- **Back up `ossec.conf` before touching it:** `cp /var/ossec/etc/ossec.conf conf/ossec.conf.bak-2026-09-08`
  (add that name to `.gitignore` — it is host config, not a deliverable), and write the rollback
  command into `docs/wazuh-manager-changes.md` beside the deploy command.
- **Do not commit.** Leave the tree dirty and report the exact `git add` line; the Owner commits.
- **Do not write** `STATE.md`, `DECISIONS.md`, `INBOX.md` — the Director's files. If you find
  something that needs a decision, write one INBOX-format block **in your report**, not in the file.
- Anything you cannot verify on this host goes into the document with the word **`unverified`**
  and the reason (DEC-025). Do not invent a config block you cannot read back.

---

## 4 · `docs/lab-scenarios.md` — write it only after the restart is confirmed

Eight categories, and only these eight. DEC-056 §Amendment and INVENTORY A8 fix the set:

| category | how it becomes live | note |
|---|---|---|
| `ssh_brute_force` | already live | 968 clusters in the archive |
| `suspicious_login` | already live | 174 |
| `privilege_escalation` | already live | 108 |
| `recon` | one ssh scan → stock `5706`/`5731`/`40601` | **nmap is not required and is not installed** |
| `malware` | ClamAV → stock decoder `0075-clamav`, rule `52502` | needs the Owner's `apt install` |
| `ransomware` | your rule 2 | |
| `data_exfiltration` | your rule 3 | |
| `c2_beacon` | your rule 4 | the 5 stock Suricata rules decode as `json` and carry no MITRE — installing Suricata classifies nothing |

**Excluded, deliberately:** `web_attack` (no web server on this host; its 8 archive clusters are
the DEC-055 mis-mapping) and `policy_violation` (no signal in any Linux stock rule — decision A5
owns it, not you).

Each block carries, in this order:

```
### <category>
Goal cluster count: <n>          (§C: 100 total, floor 60, ≥ 8/10 categories)
Run on IA1803:                   <the exact command>
Expected rule:                   <id> — <why that rule and not another>
Indexer check:                   <the curl, soc_ro, read-only>
Start:  ____:____:____           (Owner fills, local time, seconds required)
End:    ____:____:____
Observed: alerts ____  clusters ____  category ____
```

Two things the document must state at the top or G2 is unusable:

- **The lab host and the production host are the same machine.** `source='lab'` can only be tagged
  by **time window**, never by agent name. Seconds matter; a scenario with no recorded end time
  cannot be separated from production noise and is lost for both G1 and G2.
- **§C also requires ≥ 20 benign clusters on the same host** — give them their own block with a
  command, or G2 has attack traffic only and the false-positive half measures nothing.

---

## 5 · Report back

- What you wrote, file by file, with the `git add` line.
- The four logtest transcripts and the `resolve()` assertions, pasted.
- The two commands the Owner must run as root, in order, with what each one is expected to print.
- Anything marked `unverified`, and why.
