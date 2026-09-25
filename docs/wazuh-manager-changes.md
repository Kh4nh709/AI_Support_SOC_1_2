# Wazuh manager changes — IA1803, 2026-09-08

Written by the Detection Author under **DEC-056** (route B: local rules author the three
unreachable categories) and **P2-T11** design note 9 (the heartbeat rule `100999`).

Everything below was run on this host as `user1` under `sg wazuh`. Nothing here has been
committed and **the manager has not been restarted** — the two commands that need root are
in §4 and they are the Owner's.

## 0′ · 23/09 — read first: this is a third manager, not the one §0 describes

**DEC-106 (22/09):** the box moved to ATTT-M1 and stood up its own Wazuh stack from scratch —
`docker ps` shows `single-node-wazuh.manager-1` (plus `.indexer-1`, `.dashboard-1`), same
`wazuh-docker` single-node layout and the same manager version as §0's container
(`/var/ossec/VERSION.json` → `4.14.7 rc1`, commit `8c41e20`), but a different container and no
data carried over — the indexer's earliest document is `2026-09-22T07:41:28Z`. Measured fresh on
this container 23/09, not assumed from §0 or §1 below:

| thing | state on `single-node-wazuh.manager-1`, 23/09 |
|---|---|
| `/var/ossec/etc/rules/local_rules.xml` | **the stock example file**, not ours — 497 bytes, md5 `11bdb298d71a9bc09f7ebed616e5afca`, one rule (`id="100001"`). The four authored rules have never been copied into this container. |
| `conf/local_rules.xml` (this repo) | **unchanged and still correct** — 9,289 bytes, md5 `afd2ef60d7d3418cbdc27c493ad9eccf`, the same file §2 below describes. Nothing about the rule content needs re-authoring; only the deploy step is outstanding, on a new container. |
| `ossec.conf`'s heartbeat wodle (`soc_heartbeat`, lines 252–253) | **already present** on this manager — carried over by whatever restored the box, unlike the rules file. It cannot classify without `100999` (previous row), so it is currently just an unclassified `full_command` under stock rule 530. |
| indexer counts, 23/09 | `rule.id:100999` → 0, `rule.id:100301/302/303` → 0, `rule.id:100001` (the stub's own rule) → 0, `rule.id:530` → 0 — consistent with "never deployed," not with "deployed but not yet fired" |
| manager health | `wazuh-control status`: `analysisd`, `logcollector`, `remoted`, `modulesd`, `syscheckd`, `wazuh-db`, `authd`, `apid` all running; `clusterd`/`maild`/`agentlessd`/`csyslogd` not running, expected for single-node |
| enrolled agents | `agent_control -l` → `000 wazuh.manager (server)`, `001 Windows_Endpoint`, `003 pfSense.home.arpa`. **No Linux workstation agent exists on this stack** — see `docs/lab-scenarios.md` §0′, which is where this blocks the lab week, not here. |

**The deploy commands are unchanged in substance from §0.1 below — only the container name and the
path to `local_rules.xml` (a straight file copy, no `ossec.conf` edit needed for the rules
themselves) change:**

```bash
docker cp conf/local_rules.xml single-node-wazuh.manager-1:/var/ossec/etc/rules/local_rules.xml
docker exec single-node-wazuh.manager-1 chown wazuh:wazuh /var/ossec/etc/rules/local_rules.xml
docker exec single-node-wazuh.manager-1 md5sum /var/ossec/etc/rules/local_rules.xml   # expect afd2ef60d7d3418cbdc27c493ad9eccf
docker restart single-node-wazuh.manager-1
```

Both commands need whatever access level owns this host's Docker daemon — the same root-vs-`user1`
split §0.1 describes may or may not hold on ATTT-M1; this has not been re-measured, so treat the
two lines above as **the Owner's**, per this file's own rule of engagement, until shown otherwise.
After the restart, re-run this section's indexer checks; `100999` should start counting on its own
(the wodle is already live), while `100301`–`100303` stay at 0 until a scenario exists to fire
them — which needs the Linux agent from the row above first.

Everything from §0 onward below this point describes IA1803's manager (08/09–20/09) and is left
as written; it is the record of that manager, not a claim about this one.

## 0 · 14/09 — read first: the manager described below no longer exists

**20/09** — file-based checks retired (DEC-091); commands below use the indexer `_count`.

Measured 2026-09-14 22:15 as `user1`, at the Owner's instruction (Support Agent; the Owner's own
report is that the current Wazuh output is `/data/wazuh/logs/alerts/alerts.json`):

| thing | state on 14/09 |
|---|---|
| `/var/ossec` | **does not exist** — §1, §3, §4.1 and §6 name paths that are gone |
| group `wazuh` (gid 124) | **does not exist** (`getent group wazuh` → nothing); every `sg wazuh` form in this file fails with "no such group" |
| running manager | **yes, a new one** — first alert `rule 502 "Wazuh server started"` at 12:56:30Z, `manager.name` = `wazuh.manager` (was `IA1803`), ports 1514/1515/55000 listening; no `wazuh-manager` systemd unit, so §4.1's `systemctl restart wazuh-manager` has nothing to restart — how it is restarted is not visible from `user1` (`docker ps` → permission denied) |
| deployment | **the official `wazuh-docker` single-node stack, 4.14.7** — `/opt/wazuh/wazuh-docker/single-node/docker-compose.yml`, world-readable. Services `wazuh.manager` (container `8e3772d039ed`), `wazuh.indexer` (`005bea3363a9`), `wazuh.dashboard` (`af6ba99bcec7`) |
| its `ossec.conf` | **two files, and both matter.** The host's `./config/wazuh_cluster/wazuh_manager.conf` is bind-mounted to `/wazuh-config-mount/etc/ossec.conf`; the **live** file is `/var/ossec/etc/ossec.conf` inside the named volume `wazuh_etc`. **Measured 15/09, correcting this file's earlier claim: the image copies the mount into the volume only while the volume is being seeded, NOT at every start.** Proof, after a restart with the stanza in the host file: `docker exec … grep -c soc_heartbeat /var/ossec/etc/ossec.conf` → **0**, and `ossec.log` at 04:51:33 lists only the three stock commands (`df -P`, `netstat …`, `last -n 20`). A manager-config change must therefore be written into the **live** file with `docker cp`, and into the host file as well so a future fresh volume inherits it. `<rule_dir>etc/rules</rule_dir>` is line 264 of the host file, `<log_alert_level>3</log_alert_level>` line 18 |
| its `etc/rules/` | inside the **named volume `wazuh_etc`** — nothing on the host, but a `docker cp` into it survives `restart` and `docker rm` (only `compose down -v` destroys it) |
| `bin/wazuh-logtest` | inside the container; needs `sudo docker exec`, since `/var/run/docker.sock` is `1001:1001` |
| `/data/wazuh/logs/alerts/alerts.json` | mode 777, uid/gid 999 (no local name), readable by `user1`; 2,624 lines, 12:56–15:15Z (measured then via the file; since the 16/09 reboot the file is unreadable by user1 — DEC-091; every count in this document is the indexer _count) |
| `/data/wazuh/logs/alerts/2026/`, `/data/wazuh/logs/archives/` | `drwxr-x---` gid 999 — **not readable by `user1`** |
| rule `100999` on the new manager | **0**, through two rounds of diagnosis, each retracting a claim of mine. **Round 1 (11:45):** `grep -c 'soc_heartbeat\|full_command'` → 2 on the host config was read as "both terms present"; both matches are the stock `full_command` localfiles (lines 238, 245) and `soc_heartbeat` occurred **zero** times — the 08/09 stanza died with the old host. **Round 2 (12:05):** with the stanza added to the host file and the manager restarted at 04:51:15Z, `100999` was still 0 at **05:04:22Z — past the +600 s mark of 05:04**, so "not yet due" is excluded too; the cause is the row above, the live file never received it. `local_rules.xml` itself is fine and persists across restart: `ls -l /var/ossec/etc/rules/` → `-rw-rw---- wazuh wazuh 9289`, which also proves a `docker cp` into the named volume survives. **The producer is the only thing still missing, and §0.1 now edits the file the manager actually reads** |
| rules `100301`–`100303` on the new manager | **0** hits; `/var/ossec/etc/rules/local_rules.xml` (§1 "staged") went with the tree — the authored content survives only as `conf/local_rules.xml` in the repo |
| port 9400 (`INDEXER_URL`) | **dead.** The alert store is now the Wazuh indexer on **19200** (`ports: 19200:9200`), holding `wazuh-alerts-4.x-2026.09.14` with **2,968 documents** — **filebeat is shipping**. `:9200` is Graylog's OpenSearch (`CN = 79.79.79.11` / `CN = Graylog CA`), not ours |
| the new CA, and a TLS trap | the root CA is `OU = Wazuh, O = Wazuh` (valid to 2036-09-11), copied to `conf/root-ca.pem` on 15/09. **The server certificate's only SAN is `DNS:wazuh.indexer`** — so `https://127.0.0.1:19200` fails with *"no alternative certificate subject name matches target host name"*, while `https://wazuh.indexer:19200` verifies and returns 401. §6.3 forbids an insecure mode, so the URL must use the name, with `127.0.0.1 wazuh.indexer` in `/etc/hosts` (root, one line) |
| `/home/user1/archive/alerts-2026-08-08_09-07.jsonl` | **intact**, 113,379,904 bytes |

What still stands: the rule content and the §5 logtest transcripts (they prove the file parses and
matches on a 4.14.7 ruleset), and DEC-059's mechanism of record (§3 option B, `localfile`
`full_command`). Everything path-, group- and restart-shaped in §1–§4 and §6 is superseded by §0.1 below — **do not
run §4.1 as written**; it names a host path and a systemd unit that do not exist.

### 0.1 · What actually remains, measured 15/09 — one command block, and it is the Owner's

`/var/run/docker.sock` is `srw-rw---- 1001:1001`, so `user1` is denied and every line needs `sudo`.

**Done on 15/09** — `local_rules.xml` is in the container (`docker cp` at 11:34, `md5sum` verified
there: `afd2ef60d7d3418cbdc27c493ad9eccf`, 9,289 bytes, owner `wazuh:wazuh`, mode 660) and
`127.0.0.1 wazuh.indexer` is in `/etc/hosts`, so `https://wazuh.indexer:19200` verifies against
`conf/root-ca.pem` and answers 401. Absolute paths matter in the copy: a relative
`conf/local_rules.xml` resolves against the caller's shell, which is how the first attempt failed
with `lstat /home/user1/conf: no such file or directory`.

**Done 15/09 11:51, and not sufficient on its own:** `/usr/bin/date` exists in the image
(`sudo docker exec 8e3772d039ed /usr/bin/date -u +soc_heartbeat_%Y-%m-%dT%H:%M:%SZ` →
`soc_heartbeat_2026-09-15T04:51:15Z`), and the stanza is in the **host** config with a backup and a
validated XML. Keep it there — it is what a future fresh `wazuh_etc` volume inherits.

**Outstanding** — the same stanza in the **live** file, the one logcollector actually reads:

```bash
S=/tmp/claude-1000/-project-project-AI-Support-SOC-1-2/819c74a8-46c7-4532-b08f-c8bc9fb2d0a3/scratchpad/add_heartbeat_stanza.py

sudo docker cp 8e3772d039ed:/var/ossec/etc/ossec.conf /tmp/ossec.conf.live
sudo python3 $S /tmp/ossec.conf.live
sudo docker cp /tmp/ossec.conf.live 8e3772d039ed:/var/ossec/etc/ossec.conf
sudo docker exec 8e3772d039ed chown wazuh:wazuh /var/ossec/etc/ossec.conf

sudo docker exec 8e3772d039ed grep -c soc_heartbeat /var/ossec/etc/ossec.conf   # must print 2
sudo docker restart 8e3772d039ed

# immediate proof, ~40 s later — logcollector prints the command list it accepted
sleep 40; sudo grep "soc_heartbeat" /data/wazuh/logs/ossec.log | tail -3
# then, 20 minutes later — two hits 600 s apart, not one (DEC-091: via the indexer, not the file)
set -a; . ./.env; set +a
curl -s --cacert "$INDEXER_CA" -u "$INDEXER_USER:$INDEXER_PASSWORD" "$INDEXER_URL/wazuh-alerts-*/_count" -H 'Content-Type: application/json' -d '{"query":{"term":{"rule.id":"100999"}}}'   # expect count >= 2
curl -s --cacert "$INDEXER_CA" -u "$INDEXER_USER:$INDEXER_PASSWORD" "$INDEXER_URL/wazuh-alerts-*/_search" -H 'Content-Type: application/json' -d '{"query":{"term":{"rule.id":"100999"}},"size":2,"sort":[{"timestamp":"desc"}],"_source":["timestamp"]}' | jq -r '.hits.hits[]._source.timestamp'
# measured 20/09: 2026-09-20T07:57:11.812+0000 and 2026-09-20T07:47:11.657+0000 — 600.155 s apart (field is timestamp, not @timestamp)
```

`ossec.log`'s `Monitoring full output of command(600): …` line is what turns a ten-minute wait into
a forty-second one: logcollector prints exactly which commands it accepted, so a stanza that never
arrived is visible immediately instead of looking like a heartbeat that has not come round yet.

The stanza the script inserts is DEC-059's, verbatim: `<log_format>full_command</log_format>`,
`<command>/usr/bin/date -u +soc_heartbeat_%Y-%m-%dT%H:%M:%SZ</command>`,
`<alias>soc_heartbeat</alias>`, `<frequency>600</frequency>`. Rule `100999` matches
`ossec: output: 'soc_heartbeat':` under stock parent 530, which is the envelope `full_command`
plus `<alias>` produces — so the alias and the rule's `<match>` must stay spelled the same.

**Write both files, not one.** The live file is what runs; the host file is what a rebuilt volume
inherits. Neither alone survives both failure modes. The earlier instruction here — *"do not
`docker cp` an edited `ossec.conf`, the image overwrites it at every start"* — **is withdrawn**: it
was asserted from how `wazuh-docker` is documented to behave rather than from
`docker exec … grep`, which takes a second and says otherwise on this deployment. A read-only
indexer account is still outstanding and is §6.3 work (DEC-065).

The open questions are in `docs/plan/INBOX.md` 2026-09-14 · P2 / host and the 15/09 entry.

---

## 1 · State right now

| thing | state |
|---|---|
| `conf/local_rules.xml` | written, well-formed, in the repo, **uncommitted** |
| `/var/ossec/etc/rules/local_rules.xml` | **staged** — byte-identical to the repo copy (`md5 afd2ef60d7d3418cbdc27c493ad9eccf`) |
| `/var/ossec/etc/ossec.conf` | **unchanged.** The stanza in §3 has not been applied |
| `conf/ossec.conf.bak-2026-09-08` | backup of the live file taken before anything else, git-ignored |
| running manager | still on the ruleset it started with; the four rules are **not live** |

The staged file goes live at the **next restart of `wazuh-manager` for any reason**, not only
the Owner's planned one. That is intended, and it is safe in the sense that matters: the file
parses, proved in §5 by loading it into `wazuh-logtest`, and a ruleset that logtest loads is a
ruleset that will not stop the manager from starting.

Manager version, read from `/var/ossec/VERSION.json`: **4.14.7 rc1** (commit `8c41e20`).

---

## 2 · The rules file

Deployed path `/var/ossec/etc/rules/local_rules.xml`, reached by `<rule_dir>etc/rules</rule_dir>`
at `ossec.conf:282`. The directory was **empty since 2026-08-17 00:41** — the local rules that
produced `100101`/`100112`/`100200`/`100204`/`100205` in the archive are gone.

| id | level | band (DEC-054) | MITRE | category via `resolve()` | signal |
|---|---|---|---|---|---|
| `100999` | 3 | low | — | `unknown` (correct: a heartbeat is not an attack) | `ossec: output: 'soc_heartbeat':` under stock rule 530 |
| `100301` | 12 | critical | T1486 | `ransomware` | auditd execve, non-interactive symmetric encryption |
| `100302` | 10 | high | T1041 | `data_exfiltration` | auditd execve, local file uploaded by curl/wget |
| `100303` | 12 | critical | T1071 | `c2_beacon` | auditd execve, shell attached to a socket |

**Why `1003xx` and not the old block.** `100101`, `100112`, `100200`, `100204` and `100205` all
appear in the 30-day archive (`/home/user1/archive/alerts-2026-08-08_09-07.jsonl`, measured
08/09: 8 / 1935 / 4 / 5 / 467 alerts respectively). Reusing one of those ids would make the
archive's own history ambiguous, and `100112` is the subject of DEC-055.

**Why these signals and not others.** Measured on the archive on 08/09: auditd is live on this
host and the running audit ruleset carries an **execve watch keyed `exec`** (2,337 alerts),
plus `privesc` (467), `modules` (5) and `identity` (4). That watch is realtime, so a lab
scenario closes the loop in seconds. The alternative for `ransomware` — FIM rules 550/554 on a
ransom note — is a better detection but `syscheck` on this manager runs on a 12-hour schedule
(`ossec.conf:137`, no `realtime` attribute), so it cannot close a lab window. The trade is
recorded in the rule's own comment.

Each rule carries its real-world premise **and the gap in that premise** in an XML comment
above it. DEC-056 amendment 3 applies to `100301`-`100303`: the behaviour the lab generates is
real, but the detection logic that classifies it was written by the operator whose system is
being evaluated. `docs/limitations.md` is where that is stated; these comments are so a reader
of the rule can judge it without leaving the file.

---

## 3 · The `ossec.conf` change — the heartbeat producer

Only one stanza is added. Nothing existing is edited or removed.

**Insert point, against the real file as it is today:** after the `syscollector` wodle, which
ends at **line 103**, and before `<sca>` at **line 105** — i.e. on the blank line 104. That puts
it with the other three wodles (`cis-cat` line 64, `osquery` line 75, `syscollector` line 84).

### Option A — the `command` wodle (chot-v3-14-ngay.md D2's letter). **Partly `unverified`.**

```xml
  <!-- AI_Support_SOC ingest heartbeat. Rule 100999 in etc/rules/local_rules.xml
       matches this output. D2 / DEC-056 / P2-T11. -->
  <wodle name="command">
    <disabled>no</disabled>
    <tag>soc_heartbeat</tag>
    <command>/usr/bin/date -u +soc_heartbeat_%Y-%m-%dT%H:%M:%SZ</command>
    <interval>10m</interval>
  </wodle>
```

**`unverified`, and why (DEC-025).** Two things about this block cannot be checked from this
account:

1. **The element names.** `wazuh-modulesd` is `root:root` mode 750 and there is no shipped
   example of a `command` wodle anywhere under `/var/ossec` (searched `etc/`, `ruleset/`,
   `framework/`, `api/`). An unknown element inside a known wodle makes the manager refuse to
   start. The stanza is deliberately cut to the four elements needed — `run_on_start`,
   `ignore_output`, `timeout` and `verify_md5` are all omitted, so there are four names to be
   wrong about instead of eight.
2. **The output envelope.** Rule `100999` matches `ossec: output: 'soc_heartbeat':`. That
   envelope is **verified** for `<localfile>` command output (§5, transcript 1) but only
   *assumed* for the `command` wodle. If the wodle uses a different envelope the wodle will run
   and the rule will not fire — a silent zero, not a crash.

`date` is used rather than `echo` so that every beat is a distinct string; an identical
repeated line is the shape that any future de-duplication would swallow. The format string
contains no spaces, so it survives argv splitting whether or not the wodle uses a shell.

### Option B — the `localfile` full_command form. **Verified today.**

```xml
  <!-- AI_Support_SOC ingest heartbeat. Rule 100999 in etc/rules/local_rules.xml
       matches this output. D2 / DEC-056 / P2-T11. -->
  <localfile>
    <log_format>full_command</log_format>
    <command>/usr/bin/date -u +soc_heartbeat_%Y-%m-%dT%H:%M:%SZ</command>
    <alias>soc_heartbeat</alias>
    <frequency>600</frequency>
  </localfile>
```

Insert instead after the existing `last -n 20` localfile, which ends at **line 262**.

Both element names and output envelope are verified: three stanzas of exactly this shape are
running in this file today (lines 245, 251, 258), and §5 transcript 1 shows the envelope they
produce being matched by rule `100999`. `<alias>` sets the tag, exactly as
`<alias>netstat listening ports</alias>` does at line 254.

**Which to use is the Owner's call and it touches a chốt.** D2 says "wodle `command`". The
acceptance that actually binds is P2-T11's — `rule.id:100999` reaching the indexer within 30
minutes — and both options satisfy it identically. Option A is the letter of D2 with an
unverified failure mode that stops the manager; option B is a verified mechanism that deviates
from D2's wording. A decision block is in the Detection Author's report.

---

## 4 · The two commands that need root

Run in this order. Both are the Owner's; neither is run by the Detection Author.

### 4.1 · Deploy the rules and restart the manager

```bash
# 1. take the rules file to the standard ownership (it is staged as user1:wazuh 660)
sudo chown wazuh:wazuh /var/ossec/etc/rules/local_rules.xml
sudo chmod 660 /var/ossec/etc/rules/local_rules.xml

# 2. apply the chosen stanza from §3 to /var/ossec/etc/ossec.conf (editor, by hand)

# 3. restart
sudo systemctl restart wazuh-manager
```

**Expected to print:** nothing. `systemctl restart` is silent on success.

**Confirm it actually came up — do not skip this:**

```bash
systemctl is-active wazuh-manager
sudo tail -n 40 /var/ossec/logs/ossec.log
```

`is-active` must print **`active`**.

For the log, check for the *absence* of errors rather than for a particular success line: the
exact startup wording is `unverified` — this manager has not restarted since its log last
rotated (rotation is daily at 00:00 and `ossec.log` keeps no archive of previous days), so no
real startup transcript could be read back to quote. What can be stated is the error side, and
one of the two was observed directly in §5.6:

```bash
sudo grep -nE 'ERROR|CRITICAL' /var/ossec/logs/ossec.log | tail -20
```

`Error reading XML file` means the ruleset did not parse; `Invalid element in the configuration`
means the §3 stanza has a bad element name. Either way the manager is down and not alerting —
go to §6 and roll back. A clean start leaves no `ERROR` line at all: `ossec.log` as it stands on
08/09 contains none.

`ossec.log` is `wazuh:wazuh` mode 660 and `user1` is in group `wazuh`, so this grep also works
without `sudo`.

### 4.2 · Install ClamAV (for the `malware` category in `docs/lab-scenarios.md`)

```bash
sudo apt install -y clamav clamav-daemon
```

**Expected to print:** the usual apt transcript ending in `Setting up clamav-daemon`, then
`freshclam` starting a first signature download. Verify with:

```bash
command -v clamscan && systemctl is-active clamav-daemon
```

→ `/usr/bin/clamscan` and `active`. Measured 08/09 before this command: `clamscan`, `suricata`,
`nmap` and `freshclam` are all **absent**.

This is needed only for the `malware` scenario. It does not affect the four rules above and can
be done before or after the restart. The stock path it unlocks is decoder
`0075-clamav_decoders.xml` and rule **52502** *"ClamAV: Virus detected"*, level 8 — both confirmed
present in the shipped ruleset on 08/09.

---

## 5 · logtest transcripts

Fed from a file, never a pipe:

```bash
printf '<one log line>\n' > /tmp/lt.txt
sg wazuh -c '/var/ossec/bin/wazuh-logtest < /tmp/lt.txt'
```

**The banner reads `Starting wazuh-logtest ERROR`. That is not a load failure.** The literal
`ERROR` is the version string: `wazuh-logtest -V` prints `Wazuh ERROR - Wazuh Inc.` on this
install, so the framework's version lookup is what is broken, not the ruleset. It printed the
same way before `local_rules.xml` existed. Recorded because it looks exactly like the thing it
is not.

**The three audit events below are real.** They were produced by running the commands on this
host at **2026-09-08 08:41:48–08:42:38 UTC (15:41:48–15:42:38 +07:00)** and then read back out
of `/var/log/audit/audit.log` (readable without root: it is `root:adm` and `user1` is in `adm`)
and joined the way `wazuh-logcollector`'s `log_format audit` joins them. Nothing was invented.
Nothing left the host — the two network commands target `127.0.0.1:9`, which refuses.

**Control that the capture method is honest:** the same capture, applied to a plain `ps aux`,
reproduces stock rule **92604** *"Processes running for all users were queried with ps command"*
— a rule written by Wazuh, not here.

### 1 · `100999` heartbeat

```
$ printf "ossec: output: 'soc_heartbeat': soc_heartbeat_2026-09-08T08:45:00Z\n" > /tmp/lt.txt
$ sg wazuh -c '/var/ossec/bin/wazuh-logtest < /tmp/lt.txt'

**Phase 1: Completed pre-decoding.
	full event: 'ossec: output: 'soc_heartbeat': soc_heartbeat_2026-09-08T08:45:00Z'

**Phase 2: Completed decoding.
	name: 'ossec'

**Phase 3: Completed filtering (rules).
	id: '100999'
	level: '3'
	description: 'SOC pipeline heartbeat.'
	groups: '['local', 'soc_heartbeat']'
	firedtimes: '1'
	mail: 'False'
**Alert to be generated.
```

### 2 · `100301` ransomware

Command run: `openssl enc -aes-256-cbc -pbkdf2 -k S0meP4ss -in victim.dat -out victim.dat.enc`

```
argv: type=EXECVE ... argc=10 a0="/usr/bin/openssl" a1="enc" a2="-aes-256-cbc" a3="-pbkdf2"
      a4="-k" a5="S0meP4ss" a6="-in" a7="victim.dat" a8="-out" a9="victim.dat.enc"

**Phase 3: Completed filtering (rules).
	id: '100301'
	level: '12'
	description: 'Possible ransomware: non-interactive symmetric encryption via /usr/bin/openssl.'
	groups: '['local', 'ransomware']'
	firedtimes: '1'
	mail: 'True'
	mitre.id: '['T1486']'
	mitre.tactic: '['Impact']'
	mitre.technique: '['Data Encrypted for Impact']'
**Alert to be generated.
```

### 3 · `100302` data exfiltration

Command run: `curl --max-time 2 -T victim.dat http://127.0.0.1:9/`

```
argv: type=EXECVE ... argc=6 a0="/usr/bin/curl" a1="--max-time" a2="2" a3="-T"
      a4="victim.dat" a5="http://127.0.0.1:9/"

**Phase 3: Completed filtering (rules).
	id: '100302'
	level: '10'
	description: 'Possible data exfiltration: local file uploaded via /usr/bin/curl.'
	groups: '['local', 'exfiltration']'
	firedtimes: '1'
	mail: 'False'
	mitre.id: '['T1041']'
	mitre.tactic: '['Exfiltration']'
	mitre.technique: '['Exfiltration Over C2 Channel']'
**Alert to be generated.
```

### 4 · `100303` C2 channel

Command run: `bash -c 'exec 3<>/dev/tcp/127.0.0.1/9'`

```
argv: type=EXECVE ... argc=3 a0="/usr/bin/bash" a1="-c"
      a2=6578656320333C3E2F6465762F7463702F3132372E302E302E312F39

**Phase 3: Completed filtering (rules).
	id: '100303'
	level: '12'
	description: 'Possible C2 channel: shell attached to a network socket.'
	groups: '['local', 'c2_beacon']'
	firedtimes: '1'
	mail: 'True'
	mitre.id: '['T1071']'
	mitre.tactic: '['Command and Control']'
	mitre.technique: '['Application Layer Protocol']'
**Alert to be generated.
```

That hex is `exec 3<>/dev/tcp/127.0.0.1/9`. **auditd hex-encodes any execve argument containing
a space or a shell metacharacter**, so the plain-text form of this rule — the form written
first — could never have fired on the case the rule exists for. It was found by running the
command, not by reading the rule. The hex branch (`2F6465762F7463702F` = `/dev/tcp/`) is what
does the work.

### 5 · The failing cases — three lines that must not match, and do not

Each is the *same tool* as the positive above it, without the behaviour the rule claims to
detect. All three fall through to stock rule `80700` *"Audit: Messages grouped"*, level 0 —
**no alert generated**.

| command run | why it must not match | result |
|---|---|---|
| `openssl enc -aes-256-cbc -pbkdf2 -in victim.dat -out /dev/null` | no passphrase on the command line; openssl prompted `enter AES-256-CBC encryption password`, which is the interactive-admin case | `80700`, level 0 |
| `curl --max-time 2 -s -o /dev/null http://127.0.0.1:9/` | a download, the opposite direction from exfiltration | `80700`, level 0 |
| `nc -z -w1 127.0.0.1 9` | a port check with no exec option; no shell is attached | `80700`, level 0 |

### 6 · The load check is not vacuous

Both failure modes were induced on a staged copy and the good file restored afterwards.

```
=== duplicate rule id 100301 ===
** Wazuh-Logtest: WARNING: (7612): Rule ID '100301' is duplicated. Only the first occurrence will be considered.

=== malformed XML (closing tag typo) ===
** Wazuh-logtest error -1:
	ERROR: (1226): Error reading XML file 'etc/rules/local_rules.xml': XMLERR: Element 'group' not closed. (line 51).
	ERROR: (7311): Failure to initializing session
```

Note the asymmetry, because it decides how much the restart can be trusted: **malformed XML is a
hard error** and is the thing that would keep the manager down, and logtest catches it before the
restart. **A duplicate id is only a WARNING** — the manager starts and silently uses the first
occurrence. logtest will not stop that one for you.

---

## 6 · Rollback

### Rules only

```bash
sudo rm /var/ossec/etc/rules/local_rules.xml
sudo systemctl restart wazuh-manager
```

Returns `/var/ossec/etc/rules` to the empty state it was in from 2026-08-17 00:41 to
2026-09-08.

### `ossec.conf`

```bash
sudo cp /project/project/AI_Support_SOC_1_2/conf/ossec.conf.bak-2026-09-08 /var/ossec/etc/ossec.conf
sudo chown root:wazuh /var/ossec/etc/ossec.conf
sudo chmod 660 /var/ossec/etc/ossec.conf
sudo systemctl restart wazuh-manager
```

The backup is the live file as of 2026-09-08 15:40 +07:00, 9842 bytes, taken before any change.
It is git-ignored (`.gitignore`, `conf/ossec.conf.bak-*`) and **must stay that way**: it contains
the live `<integration>` `api_key` at `ossec.conf:342`.

**If the manager will not start after the restart, do the `ossec.conf` rollback first** — the
rules file is proven to parse, so the config stanza is the only new thing that can hold it down.

---

## 7 · Verification after the restart (P2-T11 acceptance)

Read-only, as `soc_ro`, from the primary checkout:

```bash
set -a; . ./.env; set +a
for id in 100999 100301 100302 100303; do
  printf 'rule.id:%s ' "$id"
  curl -s --cacert "$INDEXER_CA" -u "$INDEXER_USER:$INDEXER_PASSWORD" \
    "$INDEXER_URL/wazuh-alerts-*/_count?q=rule.id:$id"; echo
done
```

**Baseline measured 2026-09-08 08:46:47 UTC, before the restart:**

```
rule.id:100999  {"count":0,...}
rule.id:100301  {"count":0,...}
rule.id:100302  {"count":0,...}
rule.id:100303  {"count":0,...}
control (no filter)  {"count":14930,...}
```

The control is there so the zeros mean something: the query shape reaches 14,930 documents, so
the four zeros are real absences and not a broken query. Same construction as the 06/09
measurement in P2-T11 design note 9.

**Expected after the restart:**

| id | expectation | within |
|---|---|---|
| `100999` | **≥ 1** | `HEARTBEAT_MAX_AGE_MIN` = 30 minutes. End-to-end latency includes a Logstash flush (DEC-001), so allow a few minutes before calling it a failure |
| `100301` | `0` | until the lab scenario runs |
| `100302` | `0` | until the lab scenario runs |
| `100303` | `0` | until the lab scenario runs |

**Once `100999` is ≥ 1**, P2-T11 design note 9's second half applies: record one document into
`backend/tests/fixtures/indexer_heartbeat_hit.json`, drop the word `synthetic` from the test
docstring, and acceptance 5's `grep -c 'synthetic'` goes from `≥ 1` to `0`. **P2-T11 is blocked
on this and has been since 06/09.**

**If `100999` stays at 0 for more than 30 minutes with the manager `active`**, the wodle ran but
the envelope did not match — that is the §3 Option A `unverified` risk landing. The fix is
option B, and it costs one more restart, not a redesign.

---

## 8 · Things found on the way that are not this document's job

Recorded here so they are not lost; none is acted on.

1. **`ossec.conf:339-345` posts to a dead endpoint.** The `<integration>` block sends alerts at
   `<level>11</level>` and above to `http://127.0.0.1:8001/wazuh-webhook`. Measured 08/09:
   **nothing is listening on 8001** (`ss -ltn`). Rules `100301` and `100303` are level 12, so
   from the restart onward every one of their alerts will make `wazuh-integratord` attempt and
   fail a POST. Harmless to alerting — the indexer path is separate — but it will write errors
   to `ossec.log`. The path also does not match P2-T12's `POST /webhook/alerts` (DEC-040).
2. **`ossec.conf:272` excludes `0215-policy_rules.xml`.** This is a concrete reason
   `policy_violation` has no signal in any stock rule, which is inventory **A5**'s question.
   Whether re-including it is a route for A5 is the Owner's call, not the Detection Author's.
3. **The `recon` category is unaffected by DEC-055.** Checked because rule `40601` lives in
   `0280-attack_rules.xml`: its file group is `attacks` (plural), not `attack`, and `40601`
   carries MITRE `T1046` which reaches `recon` at tier 1 anyway. `5731` also carries `T1046`;
   `5706` carries `T1021.004`, which is in no tier of the resolver, and reaches `recon` at tier
   3 through its own `recon` group. So all three `recon` rules classify.
4. **`alerts.json` is readable by `user1` today — `00-context-pack.md` §6.3 says it is not.**
   Measured 08/09 with no `sudo` and no `sg`: `head -c 120 /var/ossec/logs/alerts/alerts.json`
   returns alert JSON. `/var/ossec/logs/alerts` is `drwxr-x--- wazuh:wazuh` and `alerts.json` is
   `-rw-r----- wazuh:wazuh`, and `user1` carries gid 124 (`wazuh`) as a supplementary group, which
   the kernel applies without `sg`. The context pack states the opposite — "`alerts.json` is
   **not** readable without root, so the D3/F2 file fallback is unavailable **to the
   application**" — and DEC-001 rests on it. The statement was probably true when written on
   05/09 and stopped being true when `user1` joined the group. This is not the Detection Author's
   to change; it is raised as a decision block in the report because it reopens whether the
   puller is the only path to history for the app. (measured then via the file; since the
   16/09 reboot the file is unreadable by user1 — DEC-091; every count in this document is
   the indexer _count.)

5. **The audit events this document's §5 rests on are in production data.** They were generated
   at 2026-09-08 08:41:48–08:42:38 UTC on the same host G1 draws from. They produced no alert
   under the ruleset running at the time (the rules were not live), but the raw audit records
   exist. If G1's window covers 08/09, exclude that 50-second span.
