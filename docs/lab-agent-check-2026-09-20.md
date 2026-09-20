# Lab Agent Check — 2026-09-20

**Session:** lab-agent-check · invoked per `docs/lab-scenarios.md` §1 (Pre-flight) and
`docs/wazuh-manager-changes.md` §4.2, under the hard limits of `docs/plan/prompts/owner-assist.md`
§5 (no root, no restarts, no EICAR/scenario before 22/09, write-only to scratchpad + this file,
no commits). Nothing below that needs `sudo` was run by me — every `sudo` line is a paste block
for the Owner, with expected output.

**Deadline:** the two unmeasured halves of `STATE.md`'s "KIỂM CLAMAV PHÍA AGENT (P6 việc (2))" row
— agent `<localfile>` for `/var/log/clamav/clamav.log`, and `sudo auditctl -l | grep -c execve ≥ 1`
— before the first lab window, 22/09.

## 0 · Corrections to the brief, from reading the source docs first

- `docs/wazuh-manager-changes.md` changed on disk mid-session (a live edit elsewhere, not mine),
  adding a 20/09 line that DEC-091 retired every file-based alert check for the indexer `_count`.
  That only reinforces the brief's "never the alerts.json file" instruction — no action needed.
- The step quoted in the brief as "runbook §1 step 5" (`grep -n clamav /var/ossec/etc/ossec.conf`)
  is `docs/lab-scenarios.md` §1 step 5, not `wazuh-manager-changes.md` §4.2 — §4.2 is only the
  `apt install` + rule-52502 pointer. Both are quoted in full where used below.

## 1 · What was measured (command → output)

### 1a. Task 1 — locating the agent (all non-root)

```
$ systemctl list-units | grep -i wazuh
(no output)
$ systemctl list-units --all --type=service | grep -i wazuh
(no output)
$ ls -d /var/ossec /opt/wazuh* 2>&1
ls: cannot access '/var/ossec': No such file or directory
/opt/wazuh
$ pgrep -af ossec
5148/5150/5152/5172/5179  .../wazuh_apid.py
5239  /var/ossec/bin/wazuh-authd
5253  /var/ossec/bin/wazuh-db
5287  /var/ossec/bin/wazuh-execd
5299  /var/ossec/bin/wazuh-analysisd
5323  /var/ossec/bin/wazuh-syscheckd
5357  /var/ossec/bin/wazuh-remoted
5373  /var/ossec/bin/wazuh-logcollector
5484  /var/ossec/bin/wazuh-monitord
5503  /var/ossec/bin/wazuh-modulesd
6363  s6-supervise ossec-logs
6365  tail -F /var/ossec/logs/ossec.log
$ pgrep -af wazuh
(same 11 PIDs above, plus:)
2774  .../wazuh-indexer/jdk/... org.opensearch.bootstrap.OpenSearch
4755  .../wazuh-dashboard/node/... opensearch_dashboards.yml
```

Read: this is the **manager container's own process set** — `wazuh-remoted`, `wazuh-analysisd`,
`wazuh-authd`, `wazuh-db`, `wazuh_apid.py`, `wazuh-monitord` are manager-only daemons, and
`s6-supervise ossec-logs` + `tail -F .../ossec.log` is the s6-overlay init the official
`wazuh/wazuh-manager` image uses to stream logs to `docker logs`. It's visible to a plain `pgrep`
on the host because Docker hides the host *from* a container, not a container's processes from
the host PID namespace. Matches `wazuh-manager-changes.md` §0.1's container `8e3772d039ed`.
**`wazuh-agentd` — the daemon name an actual agent runs, host or container — is absent from both
lists.**

Supplementary non-root checks, run to chase that absence down before handing this to root:

```
$ dpkg -l | grep -i wazuh
(no output — no wazuh package of any kind installed via apt on this host)
$ getent group wazuh
(no output — group does not exist, consistent with the 14/09 measurement)
$ getent passwd wazuh
(no output)
$ id wazuh
id: 'wazuh': no such user
```
A native `.deb` agent install creates a `wazuh` system user in its postinst; there is none. Weighs
against "package under another prefix," unless it was a manual tarball install that skipped that.

```
$ find /etc/systemd /lib/systemd /usr/lib/systemd -iname "*wazuh*" -o -iname "*ossec*" 2>/dev/null
(no output)
$ ls /etc/init.d/ | grep -iE 'wazuh|ossec'
(no output)
```
No unit file, no sysvinit script, anywhere readable without root.

```
$ ls -la /opt/wazuh/wazuh-docker/single-node/
docker-compose.yml  generate-indexer-certs.yml  README.md  config/
```
`docker-compose.yml` is genuinely world-readable, exactly as `wazuh-manager-changes.md` §0 says —
read directly, no `docker`, no root. It defines exactly three services — `wazuh.manager`,
`wazuh.indexer`, `wazuh.dashboard` — and **no agent**. Evidence, not proof: a fourth container
could still have been `docker run` outside this compose file.

*(Flagging, not fixing — out of scope here: that compose file carries the upstream `wazuh-docker`
template's example `INDEXER_PASSWORD` / `API_PASSWORD` / `DASHBOARD_PASSWORD` values, unrotated,
in a world-readable file. Not reproducing the strings in this doc; worth a rotation pass
separately.)*

```
$ docker ps
permission denied while trying to connect to the docker API at unix:///var/run/docker.sock
$ ls -la /var/run/docker.sock
srw-rw---- 1 1001 1001 0 Sep 16 22:24 /var/run/docker.sock
$ id
uid=1000(user1) gid=1000(user1) groups=1000(user1),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),100(users),114(lpadmin),984(docker)
```
Confirms the brief, and *why*: the socket's group is gid **1001**; `user1`'s own `docker` group is
gid **984** — a same-named, wrong-numbered group. Membership doesn't help.

### 1b. Task 2 — auditd (non-root confirmation only; the real count needs root)

```
$ systemctl is-active auditd
active
$ auditctl -l | grep -c execve
0
You must be root to run this program.
```
That `0` is `grep -c` counting matches in the *permission-denied stderr text*, not a real answer —
`auditctl` refused before printing any rules. Exactly why this has to be root's.

### 1c. Task 3 — ClamAV localfile (non-root)

```
$ dpkg -l | grep '^ii.*clamav'
ii  clamav              1.5.3+dfsg-0ubuntu0.24.04.1
ii  clamav-base         1.5.3+dfsg-0ubuntu0.24.04.1
ii  clamav-daemon       1.5.3+dfsg-0ubuntu0.24.04.1
ii  clamav-freshclam    1.5.3+dfsg-0ubuntu0.24.04.1
ii  libclamav12:amd64   1.5.3+dfsg-0ubuntu0.24.04.1
```
5 packages — matches `STATE.md:127` exactly.

```
$ ls -la /var/log/clamav/clamav.log
-rw-r----- 1 clamav adm 885 Sep 20 15:00 clamav.log
$ stat /var/log/clamav/clamav.log
Access: (0640/-rw-r-----)  Uid: (125/clamav)  Gid: (4/adm)
$ tail -5 /var/log/clamav/clamav.log
Sun Sep 20 11:00:13 2026 -> SelfCheck: Database status OK.
Sun Sep 20 12:00:13 2026 -> SelfCheck: Database status OK.
Sun Sep 20 13:00:13 2026 -> SelfCheck: Database status OK.
Sun Sep 20 14:00:13 2026 -> SelfCheck: Database status OK.
Sun Sep 20 15:00:13 2026 -> SelfCheck: Database status OK.
$ getent group adm
adm:x:4:syslog,user1
```
Mode 640 `clamav:adm`, 885 B — grew from the brief's 826 B/14:00 by exactly one more hourly
`SelfCheck` line; nothing else. No scan has touched it (none was run). **Measured, not guessed:
`user1` can read this file** — the `tail` above succeeded — because `user1` is in group `adm`
(gid 4). **Unmeasured: whether the agent's own runtime user can** — Task 1 could not locate the
agent process to `id` it, so this is a real dependency, not caution for its own sake.

### 1d. Task 4 — freshclam (non-root)

```
$ systemctl is-active clamav-freshclam
inactive
$ ls -la /var/lib/clamav/
-rw-r--r-- clamav clamav 89072577  Sep  8 16:28  main.cvd
-rw-r--r-- clamav clamav 86256640  Sep 15 14:00  daily.cld
-rw-r--r-- clamav clamav   281702  Sep  8 16:28  bytecode.cvd
             (+ .sign files, freshclam.dat)
```
`main.cvd`: 12 days old (08/09). `daily.cld`: 5 days old (15/09). Neither missing nor empty —
freshclam being inactive stalled updates, it didn't delete the database.

## 2 · Root paste blocks

### Task 1 — settle where the agent runs

```bash
sudo docker ps --format '{{.Names}} {{.Image}} {{.Status}}'
sudo find / -name ossec.conf -path '*etc*' 2>/dev/null
```
Expected: `docker ps` prints at least `wazuh.manager`/`wazuh.indexer`/`wazuh.dashboard`
(`8e3772d039ed`/`005bea3363a9`/`af6ba99bcec7`). `find` may print zero, one, or more paths —
container-only filesystems won't show here at all, only bind-mounted or host-native ones will.

**Outcome A — a fourth container appears**, not in `/opt/wazuh/wazuh-docker/single-node/docker-compose.yml`
(likely image name containing `wazuh-agent`): agent is containerized, started outside that compose
file. → Task 3 uses the **(b) container** block, and the bind-mount check is mandatory — a
container's filesystem does not inherit `/var/log/clamav` from the host by default.

**Outcome B — only the three known containers, and `find` turns up a host path** (not `/var/ossec`,
confirmed absent): a native install `user1` can't traverse to (permission on a parent dir, most
likely — `/opt/wazuh` itself is already proven traversable). → Task 3 uses the **(a) host** block,
with `<FOUND_PATH>` substituted for whatever `find` actually returns, **not** the literal
`/var/ossec` the runbook text uses.

**Outcome C, not one of the original two but real, worth naming:** neither turns up anything. Then
whatever ships `user1-IA1803` documents to the indexer (1,121 docs/7 days per the brief) isn't a
conventional `wazuh-agentd` reachable this way — Task 3 as scoped doesn't apply until that
mechanism is re-identified. Say so rather than forcing it into (a) or (b).

### Task 2 — auditd execve watch

```bash
sudo auditctl -l | grep -c execve
sudo auditctl -l | grep exec
```
Expected: first `>= 1`; second shows the actual rule text — confirms or refutes the "keyed `exec`"
claim directly instead of trusting the count alone.

**If `0`:**
```bash
echo '-a always,exit -F arch=b64 -S execve -k exec' | sudo tee -a /etc/audit/rules.d/soc-exec.rules
echo '-a always,exit -F arch=b32 -S execve -k exec' | sudo tee -a /etc/audit/rules.d/soc-exec.rules
sudo augenrules --load
sudo auditctl -l | grep -c execve
```
Expected re-check: `>= 1`. **This only adds a kernel audit rule — it does not touch Wazuh, the
manager, or any container.** Note: `wazuh-manager-changes.md:131-132`'s "running ruleset carries
an execve watch keyed `exec`" is an **08/09 measurement on the archive host**, before the 14/09
rebuild — a different, unmeasured fact from today's host-level rule count. Treat both as separate
until both are re-confirmed green.

### Task 3 — ClamAV `<localfile>`

Helper script (idempotent, safe to run twice) written to scratchpad, same pattern as
`add_heartbeat_stanza.py` in `wazuh-manager-changes.md` §0.1:
`/tmp/claude-1000/-project-project-AI-Support-SOC-1-2/7cf51efb-d588-45c8-a52f-680129fde4da/scratchpad/add_clamav_localfile.py`

**(a) if Task 1 finds a host path:**
```bash
sudo grep -n clamav <FOUND_PATH>/ossec.conf
```
If empty:
```bash
S=/tmp/claude-1000/-project-project-AI-Support-SOC-1-2/7cf51efb-d588-45c8-a52f-680129fde4da/scratchpad/add_clamav_localfile.py
sudo cp <FOUND_PATH>/ossec.conf <FOUND_PATH>/ossec.conf.bak-2026-09-20
sudo python3 "$S" <FOUND_PATH>/ossec.conf
sudo grep -c clamav <FOUND_PATH>/ossec.conf        # expect >= 1
sudo systemctl restart <unit-from-Task-1>          # NOT FILLED IN — see note below
sudo grep -c 'clamav.log' <FOUND_PATH>/../logs/ossec.log   # adjust to the real logs/ path; proves logcollector picked it up
```
The restart line is deliberately left unfilled: no systemd unit surfaced for anything wazuh-shaped
on this host (§1a), so "restart the agent" has no confirmed command yet — that's a second root
question Task 1's `find` alone won't answer. Get the real mechanism before running this line.

**(b) if Task 1 finds a container:**
```bash
sudo docker exec <AGENT_CONTAINER> grep -n clamav /var/ossec/etc/ossec.conf
sudo docker inspect <AGENT_CONTAINER> --format '{{json .Mounts}}' | grep -c clamav
```
If the mount count is `0`: **the localfile will read nothing regardless of the `ossec.conf`
edit** — the container has no path to `/var/log/clamav` at all. Add a bind mount to whatever
started that container (a `-v /var/log/clamav:/var/log/clamav:ro` run flag, or a `volumes:` line
if it has its own compose file) and recreate it — recreation is a bigger action than this check
hands over silently; stop and report it rather than scripting a fix for it here.

If the mount exists (or once added):
```bash
S=/tmp/claude-1000/-project-project-AI-Support-SOC-1-2/7cf51efb-d588-45c8-a52f-680129fde4da/scratchpad/add_clamav_localfile.py
sudo docker cp <AGENT_CONTAINER>:/var/ossec/etc/ossec.conf /tmp/ossec.conf.agent-live
sudo python3 "$S" /tmp/ossec.conf.agent-live
sudo docker exec <AGENT_CONTAINER> ls -l /var/ossec/etc/ossec.conf   # note owner:group first
sudo docker cp /tmp/ossec.conf.agent-live <AGENT_CONTAINER>:/var/ossec/etc/ossec.conf
sudo docker exec <AGENT_CONTAINER> chown <owner-from-previous-line> /var/ossec/etc/ossec.conf
sudo docker exec <AGENT_CONTAINER> grep -c clamav /var/ossec/etc/ossec.conf   # expect >= 1
sudo docker restart <AGENT_CONTAINER>
sudo docker exec <AGENT_CONTAINER> grep -c 'clamav.log' /var/ossec/logs/ossec.log   # proof logcollector accepted it
```

**Mode 640 `clamav:adm` — can the agent read it, and the fix:**
Unmeasured until Task 1 + the commands above identify the agent's runtime user. Two fixes, pick
per outcome:
- Host process running as a real user: `sudo usermod -aG adm <that-user>` (same reason `user1`
  itself can already read the file).
- Container process: check its runtime uid first — `sudo docker exec <AGENT_CONTAINER> id`. If it
  runs as **root inside the container**, permission bits don't matter, no fix needed. If it runs
  as a non-root user, that container needs its own gid-4 group membership added inside the
  image/container — bind mounts carry host UID/GID *numbers* across, not names, so matching the
  number is what matters, not matching "adm" by name.

### Task 4 — freshclam

Database present and non-trivially sized, not missing — but 5 days stale against a normally daily
cadence. **Does that block the EICAR scenario specifically?** Almost certainly not:
`Eicar-Test-Signature` has been a permanent, unchanging fixture of ClamAV's database for decades,
so a 5-day-old `daily.cld` should still match it. That's reasoned from the measured file ages and
ClamAV's known EICAR-signature behaviour, **not verified by a scan** — running one now would
violate the no-scenario-before-22/09 limit even with no real threat involved. Recommending the
fix anyway, since a SOC lab running a week-stale AV database is its own finding regardless of
EICAR:

```bash
sudo systemctl enable --now clamav-freshclam
systemctl is-active clamav-freshclam                 # expect active
sleep 30; ls -la /var/lib/clamav/daily.cld            # expect today's date, or newer than 15/09
```

## 3 · Task 5 — verification plan for 22/09 (not run now)

Quoted verbatim, `docs/lab-scenarios.md` §1:

> 3. **auditd is live and watching execve** — the three local rules hang off
> `<if_group>audit</if_group>` (`conf/local_rules.xml`'s own header comment):
> ```bash
> sudo auditctl -l | grep -c execve
> ```
> `>= 1` expected. If `0`, `ransomware`, `data_exfiltration` and `c2_beacon` cannot fire — stop and
> record it in the checklist's notes column rather than running those three scenarios blind.
>
> 4. **ClamAV is present, for `malware`** (`docs/wazuh-manager-changes.md` §4.2, quoted verbatim):
> ```bash
> sudo apt install -y clamav clamav-daemon
> command -v clamscan && systemctl is-active clamav-daemon   # expect /usr/bin/clamscan, active
> ```
>
> 5. **The agent collects ClamAV's own log** — installing the package is not enough; Wazuh has to
> be told to read `/var/log/clamav/clamav.log`:
> ```bash
> grep -n "clamav" /var/ossec/etc/ossec.conf
> ```
> If nothing is printed, add (Owner step, needs an agent restart to take effect): [the
> `<localfile>` stanza] … then restart the agent and confirm with the malware scenario itself:
> rule `52502` must appear after the EICAR scan in §3 — that is the verification, not an
> assumption made here.

And `docs/wazuh-manager-changes.md` §4.2:

> This is needed only for the `malware` scenario. It does not affect the four rules above and can
> be done before or after the restart. The stock path it unlocks is decoder
> `0075-clamav_decoders.xml` and rule **52502** *"ClamAV: Virus detected"*, level 8 — both
> confirmed present in the shipped ruleset on 08/09.

The one indexer query to run **after** the EICAR scan on 22/09 — never `alerts.json` (DEC-091):

```bash
set -a; . ./.env; set +a
curl -s --cacert "$INDEXER_CA" -u "$INDEXER_USER:$INDEXER_PASSWORD" \
  "$INDEXER_URL/wazuh-alerts-*/_count" -H 'Content-Type: application/json' \
  -d '{"query":{"term":{"rule.id":"52502"}}}'
```
Run it once **before** 22/09 too, as a baseline (expect `{"count":0,...}`, same DEC-091 discipline
as the other rule checks), so the post-scan number means something.

## 4 · Open items — needs root

- Which container or host path is `user1-IA1803`'s agent (Task 1 paste block).
- `auditctl -l | grep -c execve` real count, and the rule text.
- The agent's runtime user/uid, to settle whether it can read `/var/log/clamav/clamav.log`
  (mode 640 `clamav:adm`).
- Whether `/var/log/clamav` is bind-mounted into the agent's container (only if Task 1's outcome
  is a container).
- The agent's actual restart mechanism — no systemd unit was found on the host for anything
  wazuh-shaped, so "restart the agent" is not yet a known command.
- `<localfile>` presence/insertion in the agent's real `ossec.conf`.
- `clamav-freshclam` enablement.

## 5 · Verdict

- **auditd — blocked on root.** Service is active; the execve watch count is unmeasured
  (`auditctl -l` refuses non-root outright). Paste block above is ready to run as-is.
- **localfile — blocked on root, two levels deep.** Blocked first on Task 1 (agent not locatable
  by 5 non-root methods + 4 supplementary checks — process, package, systemd unit, init script,
  dedicated user all absent), then on the edit/restart itself once the agent is found. Not a
  single ready-to-run paste block yet — Task 1's output has to fill in `<FOUND_PATH>` /
  `<AGENT_CONTAINER>` first.
- **freshclam — not blocking, but stale.** Database present and almost certainly still carries the
  EICAR signature; not a hard blocker for the 22/09 scenario. Recommend fixing anyway before 22/09
  (paste block ready to run as-is) — a week-stale AV database in a SOC pilot is worth not shipping.
