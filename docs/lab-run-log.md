# Lab run log — G2 scenario timing

Kept by the Owner Assist, **filled in real time during the run**, not reconstructed afterwards.
Opened 2026-09-08. Absolute deadline for all runs: **11/09** — superseded; the lab week is now
**22–25/09** with labelling 26–27/09 (DEC-071's 02/10 submission date; see
`docs/plan/prompts/reload-run-2026-09-23-ATTT-M1.md`).

## 23/09 — read first: host moved, table still blank, nothing to mark

DEC-106 (22/09) moved this box to ATTT-M1, which runs its own new Wazuh stack — no history from
IA1803 came across. Checked before touching this file: **every `alerts`/`clusters`/`category
observed` cell in the table below is still blank** — no scenario in `docs/lab-scenarios.md` has
ever been run, on IA1803 or here. There is therefore no row to mark against the 20/09
17:00Z–22/09 07:41Z gap (`docs/lab-scenarios.md` §0′ point 5 makes the same check for that file).
The table's structure and the ≥8/10-categories / 100-clusters / ≥20-benign-clusters floor are
unchanged (`docs/chot-v3-14-ngay.md` §C) and this file stays the log to fill once scenarios can
run — which needs the two blockers in `docs/lab-scenarios.md` §0′ cleared first (a Linux agent
enrolled, and `conf/local_rules.xml` deployed to `single-node-wazuh.manager-1`).

The **pre-run baseline** below is IA1803's, measured 2026-09-08, and describes a manager that no
longer exists. Re-measured on ATTT-M1's own stack, 23/09, from inside the worker container
(`docker compose exec -T worker python3 -c ...` — the host itself cannot reach the indexer, no
`wazuh.indexer` line in `/etc/hosts` per DEC-106):

| figure | value | command |
|---|---|---|
| total alerts in `wazuh-alerts-*` | **1,536** | `_count`, no filter |
| earliest document | **2026-09-22T07:41:28.868Z** | `_search` sort `timestamp` asc, size 1 |
| latest document | **2026-09-23T03:25:37.849Z** | `_search` sort `timestamp` desc, size 1 |
| alerts in the last 60 min | **2** | `_count` + `range timestamp gte now-60m` |
| `rule.id:100999` (heartbeat) | **0** | `_count` term query — expected: rule not deployed yet, see `docs/wazuh-manager-changes.md` §0′ |
| `rule.id:100301`/`100302`/`100303` | **0 / 0 / 0** | same, all three local rules |
| agents seen | `Windows_Endpoint` 1,349 · `wazuh.manager` 186 · `pfSense.home.arpa` 1 | `_search` aggs on `agent.name` |
| wazuh-manager health | all core daemons running (`wazuh-control status`) | `docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control status` |

This host's own noise floor (2/hour so far, far below IA1803's measured ~34/hour) is not yet a
reliable estimate — it reflects an idle box with no lab or production Linux traffic, not a
measured steady state; re-check it once a lab agent is enrolled and running for a few hours.

## Why the seconds are the deliverable

**The lab host and the production host are the same machine (IA1803).** `source='lab'` can only
ever be tagged by **time window** — never by agent name, because there is no separate lab agent.
A scenario whose start and end seconds were not written down cannot be separated from production
noise afterwards, and is lost for **both G1 and G2**.

This is not bookkeeping. It is the tag.

Corollary, measured 2026-09-08: this host produces **~34 alerts/hour** of its own operating noise
(rules 92604, 40704, 550, 591, 80711, 80730 in a sample window). A scenario window will contain
that noise too — which is why the per-window `rule.id` breakdown below is run, not just the count.

## The floor to reach (`docs/chot-v3-14-ngay.md` §C)

- **≥ 8 of 10 categories** — the eight reachable ones are fixed by DEC-056 / inventory A8
- **100 clusters**, floor **60**
- **≥ 20 benign clusters on the same host** — §A2. The benign block is a scenario too: run it, log it.
  Without it G2 is attack traffic only and the false-positive half of the evaluation measures nothing.

## The table

One row per scenario. Fill `alerts` / `clusters` / `category observed` **after each scenario,
before starting the next** — a scenario that produced nothing is worth knowing in the same minute.

| # | category | scenario | start HH:MM:SS | end HH:MM:SS | alerts | clusters | category observed | notes |
|---|---|---|---|---|---|---|---|---|
| 1 | ssh_brute_force | | | | | | | live today (968 archive clusters) |
| 2 | suspicious_login | | | | | | | live today (174) |
| 3 | privilege_escalation | | | | | | | live today (108) |
| 4 | recon | | | | | | | stock 5706/5731/40601; **nmap not needed, not installed** |
| 5 | malware | | | | | | | needs Owner's `apt install clamav clamav-daemon`; stock 52502 |
| 6 | ransomware | | | | | | | needs local rule T1486 |
| 7 | data_exfiltration | | | | | | | needs local rule T1041 |
| 8 | c2_beacon | | | | | | | needs local rule T1071; Suricata classifies nothing |
| 9 | **benign** | | | | | | | §A2 — **≥ 20 clusters**, updates / cron / admin login |

Excluded deliberately: `web_attack` (no web server; its 8 archive clusters are the DEC-055
mis-mapping) and `policy_violation` (no signal in any Linux stock rule — decision A5 owns it).

The runnable command for each row comes from `docs/lab-scenarios.md`, which the Detection Author
writes **after** the manager restart is confirmed. Rows 1–4 and 9 need no new detection content.

## The per-window check — run after every scenario

Read-only as `soc_ro`, from the primary checkout. Substitute the row's exact start/end seconds.

```bash
set -a; . ./.env; set +a
S="2026-09-XXT00:00:00+07:00"; E="2026-09-XXT00:00:00+07:00"

# alerts in the window
curl -s --cacert "$INDEXER_CA" -u "$INDEXER_USER:$INDEXER_PASSWORD" \
  "$INDEXER_URL/wazuh-alerts-*/_count" -H 'Content-Type: application/json' \
  -d "{\"query\":{\"range\":{\"@timestamp\":{\"gte\":\"$S\",\"lte\":\"$E\"}}}}"

# which rules actually fired in the window — this is what tells you the scenario worked,
# and separates your scenario from the host's own ~34 alerts/hour
curl -s --cacert "$INDEXER_CA" -u "$INDEXER_USER:$INDEXER_PASSWORD" \
  "$INDEXER_URL/wazuh-alerts-*/_search?size=0" -H 'Content-Type: application/json' \
  -d "{\"query\":{\"range\":{\"@timestamp\":{\"gte\":\"$S\",\"lte\":\"$E\"}}},
       \"aggs\":{\"by_rule\":{\"terms\":{\"field\":\"rule.id\",\"size\":20}}}}"
```

Both forms verified working 2026-09-08 15:3x against `wazuh-alerts-*` (21 shards, all successful).

`clusters` is **not** readable from the indexer — it is the pipeline's fold
(`(rule_id, srcip, dstip, agent_name)`, `DEDUP_IDLE_GAP_MINUTES=15`, `MAX_CLUSTER_AGE_HOURS=4`,
`MAX_CLUSTER_SIZE=1000`). Until the pipeline runs over the lab window, record `alerts` as measured
and leave `clusters` blank rather than guessing. `scripts/measure_clusters.py` performs the same
fold offline and is the tool that fills the column.

## Pre-run baseline, measured 2026-09-08

| figure | value | command |
|---|---|---|
| total alerts in `wazuh-alerts-*` | **14,912** | `_count`, no filter |
| alerts in the last 60 min | **34** | `_count` + `range @timestamp gte now-60m` |
| `rule.id:100999` (heartbeat) | **0** | `_count?q=rule.id:100999` |
| `soc_ro` write attempt | **HTTP 403** | `POST .../_doc` — confirms read-only |
| wazuh-manager | `active` since 2026-09-07 14:59:36 | `systemctl is-active` |

A `0` from this indexer is a real zero, not a broken query — the unfiltered count proves the path.
