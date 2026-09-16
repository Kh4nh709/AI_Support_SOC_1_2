# Lab scenarios — the G2 runbook for `user1-IA1803` (22–24/09/2026)

Addressed to the person running the lab (the Owner). Every command in this file runs **only** on
`user1-IA1803` — never on `HR-computer` (the Windows workstation) and never on the manager itself
(`wazuh.manager`). This is a runbook, not code: nothing here is executed by an agent (P6-T05 §11 —
"you write the runbook; you do not run a scenario, install a package or touch the Wazuh manager").

## 0 · Dates and rules

- **22–24/09** — run the scenarios below. **25/09 morning** — reserve for anything that did not
  fire the first time. **25/09 afternoon** — from the primary checkout (never a worktree):
  `PYTHONPATH=backend python3 eval/build_gold.py --archive-file /home/user1/archive/alerts-2026-08-08_09-07.jsonl --g1 --g2 --lab-windows eval/lab_windows.csv --env-file .env`
  (P6-T01's command, `P6-tasks.md` §11 item 4), read `eval/gold_coverage.md`, commit the four files.
- **The seconds are the tag.** `user1-IA1803` is both the lab host and the only Linux production
  host — there is no separate lab agent (`docs/lab-run-log.md:8-11`; DEC-085, INBOX `2026-09-16 ·
  P6 / lab tagging`, option D). `source='lab'` is applied **after the fact, by time window**, never
  by agent name. A scenario whose start and end seconds are not written down cannot be told apart
  from this host's own **~34 alerts/hour of operating noise** (`docs/lab-run-log.md:15-17`) and is
  lost for both G1 and G2. This is why every command block below carries a blank
  `Start: __:__:__  End: __:__:__` line — filling it in **is** the deliverable of the day, not
  paperwork around it.
- **A category with no alert is a zero row, never a synthetic one.** If a scenario produces
  nothing, the coverage table records it as a category with zero clusters — it is excluded from
  the results and **never synthesised** (`docs/chot-v3-14-ngay.md` §A2: *"nếu không sinh được thì
  bỏ category đó khỏi bảng kết quả, không giả"*).
- **Nothing is edited in the database by hand.** The only write path from this runbook into
  `alerts` is the Wazuh pipeline itself (real traffic → puller → worker) followed by
  `eval/lab_tag.py`, which touches `source` only (never `status` — G2, `00-context-pack.md` §2).
- **Do not run scenarios on `HR-computer` or the manager.** `HR-computer` is the Windows
  workstation (agent 002) and has no relationship to any category here; the manager
  (`wazuh.manager`) is the thing watching, not the thing being watched.

#### What is actually loaded on the manager, and where this was read

The card that seeded this runbook predates two measurements; both are re-stated here, from primary
sources, before any scenario is written that depends on a rule:

1. **`conf/local_rules.xml` is in this repository** — 9,289 bytes, four rules: `100999` (heartbeat),
   `100301` (T1486 → `ransomware`), `100302` (T1041 → `data_exfiltration`), `100303` (T1071 →
   `c2_beacon`). Read directly from the file in this checkout (§3 quotes every `<match>`).
2. **The Wazuh stack was rebuilt as a Docker single-node stack on 14/09** (DEC-064: manager =
   container `8e3772d039ed`, indexer = `005bea3363a9`, dashboard = `af6ba99bcec7`, official
   `wazuh-docker` 4.14.7). DEC-069 corrected the deploy procedure: a rules-file change has to land
   in **both** the live file (`docker cp` into the container) and the host's bind-mounted
   `config/wazuh_cluster/wazuh_manager.conf`, because either alone survives only one of the two
   failure modes (a plain restart vs. a rebuilt `wazuh_etc` volume).
3. **DEC-068 (15/09 13:05, Director, read-only as `user1`) is the measurement that the four rules
   are actually loaded, not just staged:** `grep -o 'rule id="[0-9]*"' conf/local_rules.xml` →
   `100301`, `100302`, `100303`, `100999`, and it is `100999` **from that file** that is firing —
   proof the file parsed and loaded, not just that it exists on disk. Six heartbeat hits at four
   ~600.2 s intervals (`05:16:48` … `05:58:24`, all `+0000`) confirm `<frequency>600</frequency>`
   is in effect. DEC-069 separately confirms the file's durability: `local_rules.xml` inside the
   container is `-rw-rw---- wazuh wazuh 9289`, md5 `afd2ef60d7d3418cbdc27c493ad9eccf`, unchanged
   after a restart (the named volume `wazuh_etc` survives `restart` and `docker rm`, dying only on
   `compose down -v`).
4. **`grep -c '"id":"1003' /data/wazuh/logs/alerts/alerts.json` was `0` on 15/09, and DEC-068 says
   plainly this is not a failure: "those are the three lab rules … they fire only when a scenario
   runs, and no scenario has been run."** That is the state this runbook exists to change.
5. **Re-verified in this session (16/09), and it reproduces the access pattern DEC-064 describes,
   not a fresh problem:** `/data/wazuh/logs/alerts/alerts.json` and everything under
   `/data/wazuh/logs/alerts/2026/` answer **Permission denied** to `user1` from this checkout — the
   directories are `drwxr-x---`, group `systemd-journal`/gid 999, exactly as DEC-064 measured
   (`user1` is not in that group). `docker ps` also answers **permission denied while trying to
   connect to the docker API** — `/var/run/docker.sock` is not owned by the `docker` group here
   either, matching DEC-064's note. This confirms, rather than overrides, DEC-056's own statement
   that a Coder "cannot read the manager's stock ruleset … and has no network" — every `sudo`
   command in §1's pre-flight below is the **Owner's**, not something this runbook can run for you.
   Independently, `select count(*) from alerts where source='lab'` against `soc_dev` returns **0**
   (16/09) — no scenario has produced a tagged row yet, consistent with point 4.

**Consequence for what follows.** Every stock rule id this runbook expects is checked against the
30-day archive (`/home/user1/archive/alerts-2026-08-08_09-07.jsonl`, readable, 113,379,904 bytes) —
the one thing a Coder can read without the manager. An id that never fired in the archive is marked
**"(not in the archive — expected from the ruleset, unverified here)"** and is never presented as
verified; §3's per-category table says exactly which ones. The three local rules are verified
instead through `conf/local_rules.xml`'s own text, the offline `category.resolve()` function, and
the logtest transcripts already captured in `docs/wazuh-manager-changes.md` §5 (items 2–4) before
this host was rebuilt — content DEC-064's context note says explicitly "still stands."

## 1 · Pre-flight (once, before the first window, and re-checked each morning)

Run from the primary checkout on `user1-IA1803`. Every `sudo`/`docker` line is the Owner's.

1. **The pipeline is live**, so lab rows reach `alerts` in real time:
   ```bash
   make run-worker   # from the primary checkout, left running for the whole 22–24/09 window
   psql "$DATABASE_URL" -Atc "select last_seen_at from source_heartbeat"   # must be within 10 min
   ```
2. **The rules file is loaded** (DEC-068's own gate, re-run fresh — do not assume yesterday's
   answer still holds after any manager restart):
   ```bash
   grep -c '"id":"100999"' /data/wazuh/logs/alerts/alerts.json     # expect >= 2, two timestamps ~600s apart
   grep -c '"id":"1003' /data/wazuh/logs/alerts/alerts.json        # note the number — today's negative-check baseline
   ```
   If the first is `0`, stop — the four-rule file is not live on this manager right now, and no
   scenario below can produce a `1003xx` alert until it is (`docker cp conf/local_rules.xml
   8e3772d039ed:/var/ossec/etc/rules/local_rules.xml` + the DEC-069 host-file copy + a restart —
   §0.1 of `docs/wazuh-manager-changes.md`, corrected by DEC-069, is the Owner's exact procedure).
3. **auditd is live and watching execve** — the three local rules hang off `<if_group>audit</if_group>`
   (`conf/local_rules.xml`'s own header comment):
   ```bash
   sudo auditctl -l | grep -c execve
   ```
   `>= 1` expected. If `0`, `ransomware`, `data_exfiltration` and `c2_beacon` cannot fire — stop and
   record it in the checklist's notes column rather than running those three scenarios blind.
4. **ClamAV is present, for `malware`** (`docs/wazuh-manager-changes.md` §4.2, quoted verbatim):
   ```bash
   sudo apt install -y clamav clamav-daemon
   command -v clamscan && systemctl is-active clamav-daemon   # expect /usr/bin/clamscan, active
   ```
5. **The agent collects ClamAV's own log** — installing the package is not enough; Wazuh has to be
   told to read `/var/log/clamav/clamav.log`:
   ```bash
   grep -n "clamav" /var/ossec/etc/ossec.conf
   ```
   If nothing is printed, add (Owner step, needs an agent restart to take effect):
   ```xml
   <localfile>
     <log_format>syslog</log_format>
     <location>/var/log/clamav/clamav.log</location>
   </localfile>
   ```
   then restart the agent and confirm with the malware scenario itself: rule `52502` must appear
   after the EICAR scan in §3 — that is the verification, not an assumption made here.
6. **Scratch directory for every file-based scenario:**
   ```bash
   mkdir -p /tmp/lab && printf 'lab plain text\n' > /tmp/lab/plain.txt
   ```
7. **`paramiko` is not assumed for the `ssh_brute_force` loop** — checked in this checkout, not on
   the lab host (the two may differ, and §3 says so): `backend/requirements.txt` does not list it,
   and `python3 -c "import paramiko"` here raises `ModuleNotFoundError`. §3's `ssh_brute_force`
   scenario is therefore written as the manual/interactive `ssh` loop the card names as the
   fallback, not a `paramiko` script.

## 2 · The window protocol — repeat this shape for every scenario in §3

1. **Write the start second**, both forms (local wall clock is what the checklist wants; UTC is
   what the indexer stores):
   ```bash
   date -u +%FT%TZ ; date +%FT%T%z
   ```
2. **Run the command(s)** from the scenario's `#### Attack` or `#### Benign twin` block.
3. **Wait ≥ 3 minutes** before checking anything — `PULL_INTERVAL_S` is 60 s
   (`backend/app/infra/config.py:118`) and Logstash/filebeat plus the pipeline job need their own
   margin on top of it (`docs/lab-run-log.md` uses the same 3-minute rule).
4. **Write the end second** (same two commands as step 1).
5. **The per-window check**, copied from `docs/lab-run-log.md`, read-only as `soc_ro`, from the
   primary checkout — substitute this run's start/end:
   ```bash
   set -a; . ./.env; set +a
   S="<start, e.g. 2026-09-22T14:00:00+07:00>"; E="<end>"

   # alerts in the window
   curl -s --cacert "$INDEXER_CA" -u "$INDEXER_USER:$INDEXER_PASSWORD" \
     "$INDEXER_URL/wazuh-alerts-*/_count" -H 'Content-Type: application/json' \
     -d "{\"query\":{\"range\":{\"@timestamp\":{\"gte\":\"$S\",\"lte\":\"$E\"}}}}"

   # which rules actually fired — this separates the scenario from the host's own ~34/hour noise
   curl -s --cacert "$INDEXER_CA" -u "$INDEXER_USER:$INDEXER_PASSWORD" \
     "$INDEXER_URL/wazuh-alerts-*/_search?size=0" -H 'Content-Type: application/json' \
     -d "{\"query\":{\"range\":{\"@timestamp\":{\"gte\":\"$S\",\"lte\":\"$E\"}}},
          \"aggs\":{\"by_rule\":{\"terms\":{\"field\":\"rule.id\",\"size\":20}}}}"
   ```
   Each scenario in §3 additionally gives a **rule-scoped** count (its own `#### Attack` /
   `#### Benign twin` block) — that one answers "did *this* rule fire," the block above answers
   "what fired in this window at all," which is what tells noise apart from signal.
6. **Tag the window** — this is what turns "an indexer count" into `source='lab'`:
   ```bash
   PYTHONPATH=backend python3 eval/lab_tag.py \
     --agent user1-IA1803 --since "$S" --until "$E" \
     --scenario <this run's scenario_id from §5> --category <category or "benign"> \
     --kind <attack|benign> --env-file .env
   ```
   A **zero retag is not an error** — it prints `retagged 0 alerts …` and still appends a row; a
   category that produced nothing in a given window is a finding, not a bug (§0).
7. **Fill the checklist row** (§5) — `alerts`, `clusters` (leave blank until `build_gold.py --g2`
   folds the window; `alerts` alone is enough to know the scenario worked), `rules seen` (the
   `by_rule` aggregation from step 5), and check off `lab_tag run?`.

## 3 · Scenarios

Every attack command below is prefixed by §2's window protocol (steps 1–4 wrap the command; steps
5–7 follow it) and every id named as expected is checked against the archive in §0's "not in the
archive" sense. Every section ends with the label an analyst should reach — stated as the runbook's
own expectation, **not** shown to the labellers; the labelling page is blind and this file is not on
it.

### ssh_brute_force

> Playbook: `ssh_brute_force_v1`. Live today — stock rules only, no local content needed.

#### Attack

```bash
for i in $(seq 1 8); do
  ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no \
      -o StrictHostKeyChecking=no -o NumberOfPasswordPrompts=1 -o ConnectTimeout=5 \
      user1@127.0.0.1 true
  # type any wrong string at the password prompt, Enter, and move to the next iteration —
  # this loop is interactive by design (no sshpass, per the card; §1 item 7 explains why
  # this runbook does not use paramiko either)
done
```

Run all 8 inside **2 minutes** — the frequency rule below needs the burst, not just the count.

**Expected rule:** each failed attempt fires **one** of `5503` (PAM decoder path) or `5760`/`5710`
(sshd decoder path) — resolves `ssh_brute_force` either way via `T1110.001` (tier 1, exact MITRE
match), so which literal id this host emits does not change the category; the per-window `by_rule`
breakdown (§2 step 5) shows which one. **Not** `40112` ("multiple failures followed by a success")
— this scenario deliberately never succeeds, so `40112`'s own precondition never fires.

**Indexer check** (rule-scoped; run alongside §2 step 5):
```bash
curl -s --cacert "$INDEXER_CA" -u "$INDEXER_USER:$INDEXER_PASSWORD" \
  "$INDEXER_URL/wazuh-alerts-*/_count" -H 'Content-Type: application/json' \
  -d "{\"query\":{\"bool\":{\"must\":[{\"terms\":{\"rule.id\":[\"5503\",\"5760\",\"5710\"]}},{\"range\":{\"@timestamp\":{\"gte\":\"$S\",\"lte\":\"$E\"}}}]}}}"
```

**Start:** `__:__:__` (+07:00)   **End:** `__:__:__` (+07:00)

**Tag it (§2 step 6):** `PYTHONPATH=backend python3 eval/lab_tag.py --agent user1-IA1803 --since "$S" --until "$E" --scenario SBF-A<n> --category ssh_brute_force --kind attack --env-file .env`

**The loopback caveat.** `srcip = 127.0.0.1` is exactly what DEC-053 excludes from **G1** (67
loopback `ssh_brute_force` clusters, 662 alerts, dropped from the fold's pool). For **G2** it is
the lab and it is kept — this scenario has no other source address to use, and the exclusion is a
G1-only rule (`docs/plan/DECISIONS.md` DEC-053).

#### Expected rules

| id | description (as seen in the archive) | resolves to | verified how |
|---|---|---|---|
| `5710` | "sshd: Attempt to login using a non-existent user" | `ssh_brute_force` (mitre, `T1110.001`) | archive: 35,796 hits, `grep -m1 '"id":"5710"' /home/user1/archive/alerts-2026-08-08_09-07.jsonl`; resolver: `resolve(["T1110.001"],["syslog","sshd","authentication_failed","invalid_login"],"sshd",0).category == "ssh_brute_force"` |
| `5760` | "sshd: authentication failed." | `ssh_brute_force` (mitre, `T1110.001`) | archive: 1,190 hits |
| `5503` | "PAM: User login failed." | `ssh_brute_force` (mitre, `T1110.001`) | archive: 11,774 hits — this is also the fixture `backend/tests/fixtures/archive_line_5503.json` |
| `2501` | "syslog: User authentication failure." | `ssh_brute_force` (rule_groups, `authentication_failed` — no `rule.mitre` block on this one, so it resolves at tier 3) | archive: 10,411 hits; INBOX `2026-09-08 · P6 / G2` names it as one of `ssh_brute_force`'s stock ids |
| `5712` | "sshd: brute force trying to get access to the system. Non existent user." | `ssh_brute_force` (mitre, `T1110` exact) | archive: 46 hits — named only because it appears (design note 3's rule) |

The description text on `5710`/`5712` says "non-existent user" even though `user1` is a real
account; the archive's own 35,796 hits for `5710` show it is this host's dominant sshd-failure rule
regardless, and this runbook does not re-derive Wazuh's own rule text beyond what is measured.

**Expected label:** `escalate`.

#### Benign twin

A single mistyped password, corrected on the next try — the shape of a person, not a script:

```bash
ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no \
    -o StrictHostKeyChecking=no -o NumberOfPasswordPrompts=1 -o ConnectTimeout=5 \
    user1@127.0.0.1 true    # type the WRONG password once
ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no \
    -o StrictHostKeyChecking=no -o NumberOfPasswordPrompts=3 -o ConnectTimeout=5 \
    user1@127.0.0.1 true    # type the RIGHT password
```

**Expected rule:** one `5503`/`5710`/`5760` (the single failure) followed by `5715`/`5501` (the
success) — one or two events total, nowhere near the ≥8-in-2-minutes shape the frequency rule
needs, so `5712` does not fire.

**Indexer check:**
```bash
curl -s --cacert "$INDEXER_CA" -u "$INDEXER_USER:$INDEXER_PASSWORD" \
  "$INDEXER_URL/wazuh-alerts-*/_count" -H 'Content-Type: application/json' \
  -d "{\"query\":{\"bool\":{\"must\":[{\"term\":{\"rule.id\":\"5712\"}},{\"range\":{\"@timestamp\":{\"gte\":\"$S\",\"lte\":\"$E\"}}}]}}}"
```
Expected: `0` — the negative half of this twin is that the frequency rule stays silent.

**Start:** `__:__:__` (+07:00)   **End:** `__:__:__` (+07:00)

**Expected label:** `benign`.

---

### suspicious_login

> Playbook: `suspicious_login_v1`. Live today — stock rules only.

#### Attack

A success immediately after a failure burst — the "attack flavour" the card names, and honesty
about where it actually resolves:

```bash
for i in $(seq 1 3); do
  ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no \
      -o StrictHostKeyChecking=no -o NumberOfPasswordPrompts=1 -o ConnectTimeout=5 \
      user1@127.0.0.1 true    # wrong password, x3
done
ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no \
    -o StrictHostKeyChecking=no -o NumberOfPasswordPrompts=3 -o ConnectTimeout=5 \
    user1@127.0.0.1 true      # right password
```

**Expected rule:** `40112` "Multiple authentication failures followed by a success," level 12 —
**this resolves `ssh_brute_force`, not `suspicious_login`**, because its MITRE block carries both
`T1078` and `T1110` and `ssh_brute_force` outranks `suspicious_login` in `category.PRIORITY`
(`backend/app/ingest/category.py`'s tier-1 exact match collects both ids and sorts by priority —
context pack §8 names this exact case). Stated plainly: **`suspicious_login`'s own live clusters on
this host are benign-shaped** — a plain successful login is the only thing that resolves there —
and this scenario exists to show that honestly rather than paper over it with an invented
"suspicious" flavour category.py cannot produce.

**Indexer check:**
```bash
curl -s --cacert "$INDEXER_CA" -u "$INDEXER_USER:$INDEXER_PASSWORD" \
  "$INDEXER_URL/wazuh-alerts-*/_count" -H 'Content-Type: application/json' \
  -d "{\"query\":{\"bool\":{\"must\":[{\"term\":{\"rule.id\":\"40112\"}},{\"range\":{\"@timestamp\":{\"gte\":\"$S\",\"lte\":\"$E\"}}}]}}}"
```

**Start:** `__:__:__` (+07:00)   **End:** `__:__:__` (+07:00)

**Tag it (§2 step 6):** `PYTHONPATH=backend python3 eval/lab_tag.py --agent user1-IA1803 --since "$S" --until "$E" --scenario SL-A<n> --category suspicious_login --kind attack --env-file .env`

#### Expected rules

| id | description (as seen) | resolves to | verified how |
|---|---|---|---|
| `5715` | "sshd: authentication success." | `suspicious_login` (mitre, `T1078`) | archive: 124 hits |
| `5501` | "PAM: Login session opened." | `suspicious_login` (mitre, `T1078`) | archive: 923 hits |
| `40112` | "Multiple authentication failures followed by a success." | `ssh_brute_force` — **not** `suspicious_login` (mitre, `T1110` outranks `T1078`) | archive: 6 hits; resolver: `resolve(["T1078","T1110"],["syslog","attacks"],"sshd",0).category == "ssh_brute_force"` |

**Expected label:** `escalate` for the attack command above (level 12, `40112`) — while noting for
the labeller-facing evaluation chapter that the category it lands in is `ssh_brute_force`, not
`suspicious_login`.

#### Benign twin

The plain admin login this category's own clusters actually look like:

```bash
ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no \
    -o StrictHostKeyChecking=no -o NumberOfPasswordPrompts=3 -o ConnectTimeout=5 \
    user1@127.0.0.1 true    # right password, first try
```

**Expected rule:** `5715`/`5501` only — no prior failures, so `40112` cannot fire.

**Start:** `__:__:__` (+07:00)   **End:** `__:__:__` (+07:00)

**Expected label:** `benign`.

---

### privilege_escalation

> Playbook: `privilege_escalation_v1`. Live today via stock `sudo`/`rootcheck` rules.

#### Attack

```bash
sudo -k
sudo -S true <<< 'definitely-the-wrong-password'   # failed sudo
su - root -c true <<< 'also-wrong'                 # failed su, for the attack flavour
```

**Expected rule:** `5401` "Failed attempt to run sudo" (mitre_parent, `T1548.003` → `T1548`) for
the first line. The `su` failure is run and logged for completeness, but **no distinct rule id for
it survives in the 30-day archive** — a search for `pam_unix(su` in the archive finds only
successful-session lines (`5501`/`5502`); a PAM `su` failure would fall through the same generic
`authentication_failed` group path as an SSH failure, and this runbook does not invent an id for a
line the archive never shows. Treat any id the Owner actually observes here as a bonus fact for
`docs/gold-v1-report.md`, not a defined check.

**Indexer check:**
```bash
curl -s --cacert "$INDEXER_CA" -u "$INDEXER_USER:$INDEXER_PASSWORD" \
  "$INDEXER_URL/wazuh-alerts-*/_count" -H 'Content-Type: application/json' \
  -d "{\"query\":{\"bool\":{\"must\":[{\"term\":{\"rule.id\":\"5401\"}},{\"range\":{\"@timestamp\":{\"gte\":\"$S\",\"lte\":\"$E\"}}}]}}}"
```

**Start:** `__:__:__` (+07:00)   **End:** `__:__:__` (+07:00)

**Tag it (§2 step 6):** `PYTHONPATH=backend python3 eval/lab_tag.py --agent user1-IA1803 --since "$S" --until "$E" --scenario PE-A<n> --category privilege_escalation --kind attack --env-file .env`

**Rootcheck note:** `510`/`521` fire on the rootcheck schedule, not on demand — do not wait for
them inside this window; if the schedule happens to land during the lab days, the per-window
`by_rule` breakdown (§2 step 5) will show it as host noise, not as this scenario's evidence.

#### Expected rules

| id | description (as seen) | resolves to | verified how |
|---|---|---|---|
| `5402` | "Successful sudo to ROOT executed." | `privilege_escalation` (mitre_parent, `T1548.003` → `T1548`) | archive: 704 hits |
| `5401` | "Failed attempt to run sudo." | `privilege_escalation` (mitre_parent, `T1548.003` → `T1548`) | archive: 6 hits |
| `510` | "Host-based anomaly detection event (rootcheck)." | `privilege_escalation` (rule_groups, `rootcheck` — no `rule.mitre` block) | archive: 12 hits |
| `521` | "Possible kernel level rootkit" | `privilege_escalation` (rule_groups, `rootcheck`) | archive: 13 hits |

`5402`'s own level is 3 (routine administration) — DEC-055's "named, not fixed" case: whether a
successful, unremarkable `sudo` is itself worth an analyst's time is left to the labellers, not
decided here.

**Expected label:** `escalate` for the failed-sudo/failed-`su` attack; `benign` for the successful
sudo below.

#### Benign twin

```bash
sudo -k && sudo true    # correct password — routine administration
```

**Expected rule:** `5402` only, level 3.

**Start:** `__:__:__` (+07:00)   **End:** `__:__:__` (+07:00)

---

### recon

> Playbook: `recon_v1`. Live today — **nmap is not installed and not needed** (INBOX `2026-09-08 ·
> P6 / G2`).

#### Attack

```bash
for i in $(seq 1 6); do
  nc -z -w1 127.0.0.1 22
done
# or, if nc is unavailable:
ssh-keyscan -T2 127.0.0.1 ; ssh-keyscan -T2 127.0.0.1 ; ssh-keyscan -T2 127.0.0.1
```

Six probes inside a couple of minutes — the same repetition principle as `ssh_brute_force`, aimed
at a scan-detection threshold instead of an authentication one.

**Expected rule:** `5731` "SSH Scanning" and/or `40601` "Network scan from same source ip" once the
probe count crosses the manager's threshold; `5706` "insecure connection attempt (scan)" may also
fire per-probe. **Not** `5710`/`5760` — those need an actual authentication attempt (a username and
a password prompt), and `nc -z` / `ssh-keyscan` never send one. **Thin premise, stated honestly:**
`40601` is typically a correlation over *multiple distinct ports or hosts*; six probes at one port
on one host may not cross its threshold even though `5731` does — that is expected, not a scenario
failure, and the per-window `by_rule` breakdown will show exactly which of the three actually fired.

**Indexer check:**
```bash
curl -s --cacert "$INDEXER_CA" -u "$INDEXER_USER:$INDEXER_PASSWORD" \
  "$INDEXER_URL/wazuh-alerts-*/_count" -H 'Content-Type: application/json' \
  -d "{\"query\":{\"bool\":{\"must\":[{\"terms\":{\"rule.id\":[\"5706\",\"5731\",\"40601\"]}},{\"range\":{\"@timestamp\":{\"gte\":\"$S\",\"lte\":\"$E\"}}}]}}}"
```

**Start:** `__:__:__` (+07:00)   **End:** `__:__:__` (+07:00)

**Tag it (§2 step 6):** `PYTHONPATH=backend python3 eval/lab_tag.py --agent user1-IA1803 --since "$S" --until "$E" --scenario RC-A<n> --category recon --kind attack --env-file .env`

#### Expected rules

| id | description | resolves to | verified how |
|---|---|---|---|
| `5706` | "insecure connection attempt (scan)" (INBOX `2026-09-08 · P6 / G2`) | `recon` (expected via `T1046` / groups `recon`/`web_scan`/`nmap`) | **not in the archive — expected from the ruleset, unverified here** (0 hits; the stock ruleset was read directly on the manager on 08/09 via `sg wazuh`, not from this archive) |
| `5731` | "SSH Scanning" | `recon` (mitre, `T1046`) | **not in the archive — expected from the ruleset, unverified here** (0 hits) |
| `40601` | "Network scan from same source ip" | `recon` | **not in the archive — expected from the ruleset, unverified here** (0 hits) |

Table-verified regardless of archive presence: `resolve(["T1046"], [], None, 0).category ==
"recon"` and `resolve([], ["recon"], None, 0).category == "recon"` both hold against
`backend/app/ingest/category.py` as shipped.

**Expected label:** `escalate` for the repeated probe; `benign` for the single self-scan below.

#### Benign twin

```bash
ssh-keyscan -T2 127.0.0.1    # a single self scan
```

May still register one `5706` (a single probe is still a probe) — the point is that it does not
cross the repetition threshold `5731`/`40601` need, not that it is silent.

**Start:** `__:__:__` (+07:00)   **End:** `__:__:__` (+07:00)

---

### malware

> Playbook: `malware_v1`. Needs the Owner's `apt install clamav clamav-daemon` (§1 item 4).

#### Attack

```bash
{ printf 'X5O!P%%@AP[4\\PZX54(P^)7CC)7}$'; printf 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*\n'; } > /tmp/lab/eicar.com
clamdscan /tmp/lab/eicar.com
```

(Split across two `printf` calls, per the card, so this runbook file itself is never flagged by a
scanner reading it.)

**Expected rule:** `52502` "ClamAV: Virus detected" — not `80712` "Auditd: execution of a file
ended abnormally" (INBOX `2026-09-08 · P6 / G2` names `80712` as a semantically weak alternate that
carries `T1204` on *any* abnormal exit; `clamdscan` exiting because it found a virus is not an
abnormal exit, so `80712` is not expected here).

**Indexer check:**
```bash
curl -s --cacert "$INDEXER_CA" -u "$INDEXER_USER:$INDEXER_PASSWORD" \
  "$INDEXER_URL/wazuh-alerts-*/_count" -H 'Content-Type: application/json' \
  -d "{\"query\":{\"bool\":{\"must\":[{\"term\":{\"rule.id\":\"52502\"}},{\"range\":{\"@timestamp\":{\"gte\":\"$S\",\"lte\":\"$E\"}}}]}}}"
```

**Start:** `__:__:__` (+07:00)   **End:** `__:__:__` (+07:00)

**Tag it (§2 step 6):** `PYTHONPATH=backend python3 eval/lab_tag.py --agent user1-IA1803 --since "$S" --until "$E" --scenario MW-A<n> --category malware --kind attack --env-file .env`

#### Expected rules

| id | description | resolves to | verified how |
|---|---|---|---|
| `52502` | "ClamAV: Virus detected" (group `virus`, decoder `0075-clamav`) | `malware` (rule_groups `virus`, or decoder `clamd` — both map to `malware`) | **not in the archive — expected from the ruleset, unverified here** (0 hits; ClamAV was never installed during the archived 30 days). Table-verified: `resolve([], ["virus"], None, 0).category == "malware"` and `resolve([], [], "clamd", 0).category == "malware"` both hold. |

**Expected label:** `escalate` for the EICAR hit; `benign` for the clean scan below.

#### Benign twin

```bash
clamdscan /tmp/lab/plain.txt    # clean file — no virus signature
freshclam                        # signature update; record which rule, if any, fires
```

**Expected rule:** none from `clamdscan` (a clean result produces no `52502`); `freshclam`'s own
rule id, if any, is recorded in the checklist notes rather than predicted here — it was never
installed during the archived window either.

**Start:** `__:__:__` (+07:00)   **End:** `__:__:__` (+07:00)

---

### ransomware

> Local rule `100301`. Playbook: `ransomware_v1`. Reachable only through the local rule authored under DEC-056 route B —
> **DEC-056 amendment 3 applies**: the detection logic was written by the operator whose system is
> being evaluated. Named here, not buried in a footnote (§7 carries the full sentence).

#### Attack

```bash
openssl enc -aes-256-cbc -salt -in /tmp/lab/plain.txt -out /tmp/lab/plain.txt.enc -k labpass
gpg --batch --symmetric --passphrase labpass /tmp/lab/plain.txt
```

**Expected rule:** `100301` — satisfies `conf/local_rules.xml`'s own `<match type="pcre2">` on
`audit.exe` ending in `openssl`/`gpg`/`gpg2`:
`a\d+="enc".*a\d+="-(?:k|pass|kfile)"|a\d+="(?:-c|--symmetric)".*a\d+="--(?:batch|passphrase|passphrase-fd|passphrase-file)"`
— the `openssl` line matches the first alternative (`enc` + `-k`), the `gpg` line matches the
second (`--symmetric` + `--passphrase`). **Not** `100302`/`100303` — neither command's `audit.exe`
matches `curl`/`wget`/`nc`/`bash`, so the other two local rules' `<field name="audit.exe">` never
even reaches their `<match>`.

**Indexer check:**
```bash
curl -s --cacert "$INDEXER_CA" -u "$INDEXER_USER:$INDEXER_PASSWORD" \
  "$INDEXER_URL/wazuh-alerts-*/_count" -H 'Content-Type: application/json' \
  -d "{\"query\":{\"bool\":{\"must\":[{\"term\":{\"rule.id\":\"100301\"}},{\"range\":{\"@timestamp\":{\"gte\":\"$S\",\"lte\":\"$E\"}}}]}}}"
```

**Start:** `__:__:__` (+07:00)   **End:** `__:__:__` (+07:00)

**Tag it (§2 step 6):** `PYTHONPATH=backend python3 eval/lab_tag.py --agent user1-IA1803 --since "$S" --until "$E" --scenario RW-A<n> --category ransomware --kind attack --env-file .env`

#### Expected rules

| id | description (as authored) | resolves to | verified how |
|---|---|---|---|
| `100301` | "Possible ransomware: non-interactive symmetric encryption via $(audit.exe)." | `ransomware` (mitre, `T1486` exact) | `conf/local_rules.xml` (repo, quoted above); DEC-068 confirms the file is loaded on the manager (§0); resolver: `resolve(["T1486"], ["local","audit","ransomware"], None, 0).category == "ransomware"`; logtest transcript captured pre-rebuild in `docs/wazuh-manager-changes.md` §5 item 2 (`openssl enc -aes-256-cbc -pbkdf2 -k S0meP4ss …` → `id: '100301'`, `mitre.id: ['T1486']`) |

**Expected label:** `escalate`.

#### Benign twin

The rule's own stated benign case — the same tool, prompted instead of scripted:

```bash
openssl enc -aes-256-cbc -salt -in /tmp/lab/plain.txt -out /tmp/lab/plain2.enc   # no -k: interactive prompt
```

**Expected rule:** none — no passphrase on the command line means the `<match>` never fires; this
is exactly the interactive-admin case `docs/wazuh-manager-changes.md` §5 item 5 already proved
falls through to stock `80700` ("Audit: Messages grouped", level 0, no alert).

**Start:** `__:__:__` (+07:00)   **End:** `__:__:__` (+07:00)

**Expected label:** `benign` / `false_positive`.

#### Negative check

**Before:** `grep -c '"id":"100301"' /data/wazuh/logs/alerts/alerts.json` → record the count.
**After** the benign twin above: re-run the same command.

**Expected:** the count is **unchanged**. A test that requires a `pass`/`k`/`kfile` flag before it
fires must stay silent on the one command that omits it — that is the whole point of authoring the
rule as a behavioural property (§3's header comment) rather than as "`openssl` ran".

---

### data_exfiltration

> Local rule `100302`. Playbook: `data_exfiltration_v1`. Reachable only through the local rule — DEC-056 amendment 3
> applies here too.

#### Attack

```bash
curl --max-time 2 -T /tmp/lab/plain.txt http://127.0.0.1:9/
curl --max-time 2 -F 'f=@/tmp/lab/plain.txt' http://127.0.0.1:9/
```

Port 9 (discard) refuses the connection on this host — the point is the execve auditd records, not
a successful transfer.

**Expected rule:** `100302` — matches
`a\d+="(?:-T|--upload-file)"|a\d+="--post-file|a\d+="(?:-F|--form|-d|--data|--data-binary|--data-raw)".*a\d+="[^"]*@/`:
the first `curl` line matches `-T`, the second matches `-F` with a `@`-prefixed local path. **Not**
`100301`/`100303` — `curl`'s `audit.exe` never matches `openssl`/`gpg`/`nc`/`bash`.

**Indexer check:**
```bash
curl -s --cacert "$INDEXER_CA" -u "$INDEXER_USER:$INDEXER_PASSWORD" \
  "$INDEXER_URL/wazuh-alerts-*/_count" -H 'Content-Type: application/json' \
  -d "{\"query\":{\"bool\":{\"must\":[{\"term\":{\"rule.id\":\"100302\"}},{\"range\":{\"@timestamp\":{\"gte\":\"$S\",\"lte\":\"$E\"}}}]}}}"
```

**Start:** `__:__:__` (+07:00)   **End:** `__:__:__` (+07:00)

**Tag it (§2 step 6):** `PYTHONPATH=backend python3 eval/lab_tag.py --agent user1-IA1803 --since "$S" --until "$E" --scenario DX-A<n> --category data_exfiltration --kind attack --env-file .env`

#### Expected rules

| id | description (as authored) | resolves to | verified how |
|---|---|---|---|
| `100302` | "Possible data exfiltration: local file uploaded via $(audit.exe)." | `data_exfiltration` (mitre, `T1041` exact — tier 1 wins before the `exfiltration` group is even consulted) | `conf/local_rules.xml` (repo); resolver: `resolve(["T1041"], ["local","audit","exfiltration"], None, 0).category == "data_exfiltration"`; logtest transcript pre-rebuild in `docs/wazuh-manager-changes.md` §5 item 3 (`curl --max-time 2 -T victim.dat http://127.0.0.1:9/` → `id: '100302'`, `mitre.id: ['T1041']`) |

**Expected label:** `escalate`.

#### Benign twin

```bash
curl --max-time 2 -s -o /dev/null http://127.0.0.1:9/x   # a download — the opposite direction
```

**Expected rule:** none — `docs/wazuh-manager-changes.md` §5 item 5 already proved this exact
download command falls through to `80700`, level 0.

**Start:** `__:__:__` (+07:00)   **End:** `__:__:__` (+07:00)

**Expected label:** `benign` / `false_positive`.

#### Negative check

**Before:** `grep -c '"id":"100302"' /data/wazuh/logs/alerts/alerts.json` → record the count.
**After** the benign twin above: re-run the same command.

**Expected:** the count is **unchanged** — a download never matches the upload-shaped `<match>`.

---

### c2_beacon

> Local rule `100303`. Playbook: `c2_beacon_v1`. Reachable only through the local rule — DEC-056 amendment 3 applies
> here too, and the rule's own docstring is explicit that it detects **channel setup**, not
> beaconing periodicity (§7 repeats this for the report).

#### Attack

```bash
bash -c 'exec 3<>/dev/tcp/127.0.0.1/9'
nc -h 2>&1 | grep -q -- '-e' && nc -e /bin/sh 127.0.0.1 9   # only if this nc build has -e
```

**Expected rule:** `100303` — the `bash` line matches the rule's **hex branch**, not its plain-text
one: auditd hex-encodes any execve argument containing a shell metacharacter, so `/dev/tcp/127.0.0.1/9`
is recorded as `2F6465762F7463702F...`, and it is
`(?:a\d+=|proctitle=)[0-9A-F]*2F6465762F(?:7463|7564)702F` that matches, never the plain-text
alternative in the same `<match>` — `conf/local_rules.xml`'s own comment on `100303` explains this
was found by running the command, not by reading the rule. The `nc -e` line (run only when the
local build supports `-e`, tested first — most distributions compile it out) matches the third
alternative, `exe="…/(?:nc|…)".*a\d+="(?:-e|…)"`. **Not** `100301`/`100302` — neither `bash` nor
`nc` is `openssl`/`gpg`/`curl`/`wget`.

**Indexer check:**
```bash
curl -s --cacert "$INDEXER_CA" -u "$INDEXER_USER:$INDEXER_PASSWORD" \
  "$INDEXER_URL/wazuh-alerts-*/_count" -H 'Content-Type: application/json' \
  -d "{\"query\":{\"bool\":{\"must\":[{\"term\":{\"rule.id\":\"100303\"}},{\"range\":{\"@timestamp\":{\"gte\":\"$S\",\"lte\":\"$E\"}}}]}}}"
```

**Start:** `__:__:__` (+07:00)   **End:** `__:__:__` (+07:00)

**Tag it (§2 step 6):** `PYTHONPATH=backend python3 eval/lab_tag.py --agent user1-IA1803 --since "$S" --until "$E" --scenario C2-A<n> --category c2_beacon --kind attack --env-file .env`

#### Expected rules

| id | description (as authored) | resolves to | verified how |
|---|---|---|---|
| `100303` | "Possible C2 channel: shell attached to a network socket." | `c2_beacon` (mitre, `T1071` exact) | `conf/local_rules.xml` (repo); resolver: `resolve(["T1071"], ["local","audit","c2_beacon"], None, 0).category == "c2_beacon"`; logtest transcript pre-rebuild in `docs/wazuh-manager-changes.md` §5 item 4 (`bash -c 'exec 3<>/dev/tcp/127.0.0.1/9'` → `id: '100303'`, `mitre.id: ['T1071']`, hex argv confirmed) |

**Expected label:** `escalate`.

#### Benign twin

```bash
nc -z -w1 127.0.0.1 22    # a port check, no -e — no shell attached
```

**Expected rule:** none — `docs/wazuh-manager-changes.md` §5 item 5 already proved this exact
command falls through to `80700`, level 0.

**Start:** `__:__:__` (+07:00)   **End:** `__:__:__` (+07:00)

**Expected label:** `benign` / `false_positive`.

#### Negative check

**Before:** `grep -c '"id":"100303"' /data/wazuh/logs/alerts/alerts.json` → record the count.
**After** the benign twin above: re-run the same command.

**Expected:** the count is **unchanged** — a bare port check never attaches a shell, so neither the
hex branch nor the plain-text branch of the `<match>` fires.

## 4 · The benign block

Run **once per day** (22, 23, 24/09), as its own `--kind benign --category benign` window —
`docs/chot-v3-14-ngay.md` §A2's benign activity on the same host, run deliberately so the labellers
never learn "lab host = escalate" from hostname alone:

```bash
sudo apt update && sudo apt -s upgrade   # package listing / simulated upgrade — no state change forced
crontab -l                                # inspect the existing cron jobs (read-only, generates its own log line)
ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no \
    -o StrictHostKeyChecking=no -o NumberOfPasswordPrompts=3 -o ConnectTimeout=5 \
    user1@127.0.0.1 true                  # admin login, correct password first try
ssh-keyscan -T2 127.0.0.1                 # self scan
```

**Expected rules:** `5715`/`5501` (the admin login), `2701`/`2930`-class apt/dpkg noise, whatever
`crontab -l` triggers (recorded in the checklist notes, not predicted), and a single `5706`/none
from the self scan — this window's alerts "resolve to whatever they resolve to" (design note 1);
that is why it is tagged `--category benign` rather than one specific category. Together with this
host's own ~34 alerts/hour of noise falling inside the window, this is where most of the ≥ 20
benign lab clusters (§ floor, `docs/lab-run-log.md` §"The floor to reach") come from.

**Start:** `__:__:__` (+07:00)   **End:** `__:__:__` (+07:00) — one line per day, three total.

**Tag it (§2 step 6):** `PYTHONPATH=backend python3 eval/lab_tag.py --agent user1-IA1803 --since "$S" --until "$E" --scenario BB-D<n> --category benign --kind benign --env-file .env`

## 5 · Checklist

Pre-filled with the scenario ids used in §3's examples. **Interleave, do not batch**: run each
day's rows in the order listed (not all four repeats of one category back to back) — the cluster
key is `(rule_id, srcip, dstip, agent_name)` and `IDLE_GAP` is 15 minutes
(`00-context-pack.md` §5), so two runs of the *same* category 5 minutes apart merge into one
cluster, while running a *different* category in between naturally clears the 20-minute spacing
rule with no idle waiting. Target: **4 attack runs per category over the three days ≈ 32 attack
clusters**, plus the benign twins, plus the three benign-block windows.

| # | category | kind | scenario_id | start | end | alerts | clusters | rules seen | lab_tag run? | notes |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | ssh_brute_force | attack | `SBF-A1` | | | | | | ☐ | day 1 |
| 2 | suspicious_login | attack | `SL-A1` | | | | | | ☐ | day 1 |
| 3 | privilege_escalation | attack | `PE-A1` | | | | | | ☐ | day 1 |
| 4 | recon | attack | `RC-A1` | | | | | | ☐ | day 1 |
| 5 | malware | attack | `MW-A1` | | | | | | ☐ | day 1 |
| 6 | ransomware | attack | `RW-A1` | | | | | | ☐ | day 1 |
| 7 | data_exfiltration | attack | `DX-A1` | | | | | | ☐ | day 1 |
| 8 | c2_beacon | attack | `C2-A1` | | | | | | ☐ | day 1 |
| 9 | **benign** | benign | `BB-D1` | | | | | | ☐ | day 1, §4 |
| 10 | ssh_brute_force | attack | `SBF-A2` | | | | | | ☐ | day 2 |
| 11 | suspicious_login | attack | `SL-A2` | | | | | | ☐ | day 2 |
| 12 | privilege_escalation | attack | `PE-A2` | | | | | | ☐ | day 2 |
| 13 | recon | attack | `RC-A2` | | | | | | ☐ | day 2 |
| 14 | malware | attack | `MW-A2` | | | | | | ☐ | day 2 |
| 15 | ransomware | attack | `RW-A2` | | | | | | ☐ | day 2 |
| 16 | data_exfiltration | attack | `DX-A2` | | | | | | ☐ | day 2 |
| 17 | c2_beacon | attack | `C2-A2` | | | | | | ☐ | day 2 |
| 18 | ssh_brute_force | benign | `SBF-B1` | | | | | | ☐ | day 2, twin |
| 19 | suspicious_login | benign | `SL-B1` | | | | | | ☐ | day 2, twin |
| 20 | privilege_escalation | benign | `PE-B1` | | | | | | ☐ | day 2, twin |
| 21 | recon | benign | `RC-B1` | | | | | | ☐ | day 2, twin |
| 22 | malware | benign | `MW-B1` | | | | | | ☐ | day 2, twin |
| 23 | ransomware | benign | `RW-B1` | | | | | | ☐ | day 2, twin (negative check) |
| 24 | data_exfiltration | benign | `DX-B1` | | | | | | ☐ | day 2, twin (negative check) |
| 25 | c2_beacon | benign | `C2-B1` | | | | | | ☐ | day 2, twin (negative check) |
| 26 | **benign** | benign | `BB-D2` | | | | | | ☐ | day 2, §4 |
| 27 | ssh_brute_force | attack | `SBF-A3` | | | | | | ☐ | day 3 |
| 28 | suspicious_login | attack | `SL-A3` | | | | | | ☐ | day 3 |
| 29 | privilege_escalation | attack | `PE-A3` | | | | | | ☐ | day 3 |
| 30 | recon | attack | `RC-A3` | | | | | | ☐ | day 3 |
| 31 | malware | attack | `MW-A3` | | | | | | ☐ | day 3 |
| 32 | ransomware | attack | `RW-A3` | | | | | | ☐ | day 3 |
| 33 | data_exfiltration | attack | `DX-A3` | | | | | | ☐ | day 3 |
| 34 | c2_beacon | attack | `C2-A3` | | | | | | ☐ | day 3 |
| 35 | ssh_brute_force | attack | `SBF-A4` | | | | | | ☐ | day 3, ≥20 min after row 27 |
| 36 | suspicious_login | attack | `SL-A4` | | | | | | ☐ | day 3, ≥20 min after row 28 |
| 37 | privilege_escalation | attack | `PE-A4` | | | | | | ☐ | day 3, ≥20 min after row 29 |
| 38 | recon | attack | `RC-A4` | | | | | | ☐ | day 3, ≥20 min after row 30 |
| 39 | malware | attack | `MW-A4` | | | | | | ☐ | day 3, ≥20 min after row 31 |
| 40 | ransomware | attack | `RW-A4` | | | | | | ☐ | day 3, ≥20 min after row 32 |
| 41 | data_exfiltration | attack | `DX-A4` | | | | | | ☐ | day 3, ≥20 min after row 33 |
| 42 | c2_beacon | attack | `C2-A4` | | | | | | ☐ | day 3, ≥20 min after row 34 |
| 43 | **benign** | benign | `BB-D3` | | | | | | ☐ | day 3, §4 |

Excluded deliberately from every row above: `web_attack`, `policy_violation` (§7 says why).

## 6 · After the last window (25/09)

```bash
# from the primary checkout
PYTHONPATH=backend python3 eval/build_gold.py \
  --archive-file /home/user1/archive/alerts-2026-08-08_09-07.jsonl \
  --g1 --g2 --lab-windows eval/lab_windows.csv --env-file .env
```

Read `eval/gold_coverage.md`. It must show **G2 ≥ 60** (floor; target 100) with every one of the
eight categories in §3 listed — a category that produced zero clusters is a **zero row**, printed
as such, **never synthesised** (§0). `≥ 20` of G2's clusters must be benign (checked after
labelling, by `label_export.py report` — not a selection rule, `P6-tasks.md` planning decision 10).
Commit `eval/gold_candidates.csv`, `eval/g1_clusters.csv`, `eval/g1_members.csv.gz`,
`eval/gold_coverage.md`, and `eval/lab_windows.csv` with its now-populated rows (this runbook ships
the file with its header only — every row after it is the Owner's).

## 7 · What is deliberately not here

- **`web_attack`** — no web server runs on `user1-IA1803` and none of its 8 archive clusters are
  anything but the `GROUP_TO_CATEGORY["attack"]` mis-mapping DEC-055 already removed; a scenario
  here would classify nothing (DEC-055, DEC-056).
- **`policy_violation`** — no Linux stock rule carries a fitting group and no local rule was
  authored for it; it has no signal at all, not a weak one (DEC-057, which decided it inside A5
  rather than here).
- **Suricata** — installing it classifies nothing on this estate: its five stock rules decode as
  `json`, carry no MITRE id and no mapped group, so `DECODER_TO_CATEGORY["suricata"]` can never
  match (INBOX `2026-09-08 · P6 / G2`; `docs/chot-v3-14-ngay.md` §A2's own warning, confirmed by
  construction rather than assumed).
- **The circularity in `ransomware`/`data_exfiltration`/`c2_beacon`, named plainly.** The behaviour
  these three scenarios generate is real, but the detection logic that classifies it —
  `conf/local_rules.xml`'s three rules — was written by the same person whose system this project
  evaluates (DEC-056 amendment 3). That is a defensible engineering trade-off on a single-operator
  estate, the same shape as the author-as-labeller control this project already names, but it is
  stated here rather than left as a runbook footnote, and the evaluation chapter (P8's
  `docs/limitations.md`) carries it forward for exactly these three categories.
