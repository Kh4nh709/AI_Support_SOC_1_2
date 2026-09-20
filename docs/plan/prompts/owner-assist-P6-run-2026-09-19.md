# Owner Assist — the P6 week (19/09 → 28/09): everything mechanical in the seven items, so the Owner does only what needs a human or root

**Invocation (the Owner pastes this, nothing else — session name `owner-assist-P6`, keep it open all week):**

```
Read docs/plan/prompts/owner-assist.md and act as the Owner Assist. Then read
docs/plan/prompts/owner-assist-P6-run-2026-09-19.md — it replaces that prompt's §1–§3 and §6 for
this week. Start with §0 tonight.
```

`prompts/owner-assist.md` §4 (batched intake) and §5 (hard limits) still govern. You sit beside the
Owner at the keyboard; you run what needs no root, you hand over — as one paste block with its
expected output — what does. You write **only** to `docs/plan/INBOX.md` (append) and to the files
named in §3–§5; product code, `STATE.md`, `DECISIONS.md` are never yours. The seven items you are
splitting are `STATE.md:89` (P6) and the two 20/09 checks at `:104–105`. Written by the Support
Agent at the Owner's instruction, 19/09 17:00; the facts in §0 were measured then.

## 0 · Tonight — the worker, because nothing in the lab lands without it

**Measured 19/09 16:19:** no `app.web.worker` process since the reboot of 16/09 22:24. In `soc_dev`:
`alerts` = `replay` 92,011 + `wazuh` 3,941 (unchanged since DEC-079); `jobs`: `pull` **1 pending**,
`pipeline` 95,971 succeeded, `triage` **383 pending**; `source_cursor.last_sort 1789477112587`,
`last_pull_at 2026-09-15 20:05:33`; the indexer holds **7,352** documents — ≈ 3,400 live ones are
waiting behind that cursor.

`make run-worker` runs `app.web.worker`, whose handler table is **`pull` + `pipeline` only**
(`backend/app/web/worker.py:24`); it enqueues one `pull` job at start (a no-op while one is
pending — there is). The 383 `triage` jobs stay pending until P3's ① lands and the worker is
restarted with the new handlers — that is expected, not a fault.

Start it from the **primary checkout** (it needs `.env`), detached, with a log outside the repo:

```bash
cd /project/project/AI_Support_SOC_1_2
mkdir -p /home/user1/soc-logs
PYTHONUNBUFFERED=1 nohup setsid make run-worker > /home/user1/soc-logs/worker-$(date +%F).log 2>&1 &   # PYTHONUNBUFFERED=1 added 20/09 (DEC-099): unbuffered log lines, no product change
echo $! > /home/user1/soc-logs/worker.pid; sleep 20; tail -n 20 /home/user1/soc-logs/worker-$(date +%F).log
```

Then prove it, with these three and nothing softer:

```bash
D="$(grep '^DATABASE_URL=' .env | cut -d= -f2-)"
psql "$D" -Atc "select last_sort, last_pull_at, last_error from source_cursor"      # last_pull_at advances past 2026-09-15 20:05
psql "$D" -Atc "select count(*) from alerts where source='wazuh'"                   # rises from 3,941 toward ~7,300
psql "$D" -Atc "select last_seen_at from source_heartbeat"                          # within 10 minutes of now
```

Paste the three outputs into an INBOX entry `2026-09-19 · P6 / worker · BLOCKER` marked
**cleared by measurement** — it is also the first proof that P2-T11's cursor survived a real reboot,
which the Director will want for a DEC. If `last_error` is non-null, stop and hand the Owner the
log; do not restart in a loop. **Restart the worker after every merge that touches
`backend/app/web/worker.py`, `soar/`, `infra/puller.py`** — P3-T09/T10/T11 will.

## 1 · The two 20/09 checks — you carry them to the Owner, you do not answer them

- **Labeller names and dates** (`STATE.md:105`): two people, independent, blind, own random order,
  no exchange, ~200 clusters per session (`tasks/P6/P6-tasks.md §10`), on **26–27/09**. Ask for
  the names in the morning; write the answer into an INBOX entry the Director moves to `STATE.md`.
  If only one name exists by evening, record that too — it is a fact the plan must react to, not
  a reason to wait.
- **The ② decision** (DEC-090: the trigger is inert, the Owner chooses A′ cut-now or A″ re-armed
  trigger). Not yours; just make sure it is answered on 20/09 and in INBOX.
- The advisor's `admin` account waits for **P4-T01's seed CLI** — track it; do not improvise a
  user by SQL.

## 2 · Pre-flight for the lab (before 22/09) — from the runbook as corrected by DEC-091

`docs/lab-scenarios.md` is on `task/P6-T05` (in review); read it there until it merges. DEC-091
replaced every `alerts.json` grep with an indexer count — the file is unreadable by `user1` since
the reboot (mode 640) — so **every check below goes through the indexer with `.env`'s `soc_ro`**:

```bash
set -a; . ./.env; set +a
H() { curl -s --cacert "$INDEXER_CA" -u "$INDEXER_USER:$INDEXER_PASSWORD" "$INDEXER_URL/$INDEXER_INDEX/_count" -H 'Content-Type: application/json' -d "$1"; echo; }
H '{"query":{"term":{"rule.id":"100999"}}}'        # heartbeat: count grows by 1 every 600 s (521 at 09:16Z on 19/09)
H '{"query":{"prefix":{"rule.id":"1003"}}}'        # the three lab rules: MUST be 0 before the first window — that is the negative baseline
```

What needs root — hand each over as a block, with the expected output, and record the Owner's
paste in INBOX:

| item | command (the Owner runs) | expect |
|---|---|---|
| clamav on the agent host — packages are already installed (measured: 4 `clamav*` packages) | `clamscan --version` · then the agent-side `<localfile>` for `/var/log/clamav/clamav.log` — **find the agent first**: `sudo docker ps --format '{{.Names}} {{.Image}}' \| grep agent` (a `wazuh/wazuh-agent:4.14.7` compose exists at `/opt/wazuh/wazuh-docker/wazuh-agent/`; no `wazuh-agentd` is visible on the host) | version line; agent container name |
| auditd watches `execve` (the three `1003xx` rules hang on group `audit`) | `sudo auditctl -l \| grep -c execve` | `≥ 1` |
| a fresh EICAR drop produces rule `52502` (malware, DEC-056) | per `lab-scenarios.md §3 malware` | `H '{"query":{"term":{"rule.id":"52502"}}}'` → `≥ 1` |

If the agent turns out to be a container, its `ossec.conf` obeys the same rule the manager's
did (DEC-069): the change goes into the **live** file by `docker cp` **and** into the compose
config so a rebuilt volume inherits it. Do not repeat DEC-064's mistake.

## 3 · The windows, 22–24/09 — the timing log is the deliverable (owner-assist.md §2 still applies)

The Owner runs each scenario on `user1-IA1803`; you keep the clock and the record. Per category,
**four runs ≥ 20 minutes apart** (`DEDUP_IDLE_GAP_MINUTES=15`: two runs 5 minutes apart are one
cluster); the benign block one window per day. For every window:

1. Before: the two `H` counts above, plus the category's expected rule id from the runbook.
2. Start/end **to the second** (`date -u +%FT%TZ` before and after) — you type them, not the Owner.
3. After ≥ 5 minutes (indexer lag + pipeline): the counts again, and in the DB
   `psql "$D" -Atc "select count(*) from alerts where alert_time between '<start>' and '<end>'"`.
4. Then the retag, from the primary checkout, exactly:
   ```bash
   PYTHONPATH=backend python3 eval/lab_tag.py --agent user1-IA1803 --since <start> --until <end> \
     --scenario <name> --category <category> --kind attack|benign --env-file .env
   ```
   and prove it: `psql "$D" -Atc "select source, count(*) from alerts where alert_time between '<start>' and '<end>' group by 1"` → the window's rows are `lab`.
5. Append the window to `eval/lab_windows.csv` in the runbook's format; `git add` it and show
   the Owner the diff — **the Owner commits** (outside `docs/plan/`, HUONG-DAN §186).

A category whose expected rule never fires is **recorded as such, never synthesised**
(`prompts/director-optimized.md` incident table). Say it in the INBOX entry with the counts.

## 4 · 25/09 afternoon — build the gold candidates (needs P6-T01 merged; check `git log --oneline main | grep 'P6-T01 merged'` first)

```bash
PYTHONPATH=backend python3 eval/build_gold.py --archive-file /home/user1/archive/alerts-2026-08-08_09-07.jsonl \
  --g1 --g2 --lab-windows eval/lab_windows.csv --env-file .env \
  --take-all-crit-high --unknown-cap-pct 40 --category-floor 25        # DEC-086 defaults
```

Then read `eval/gold_coverage.md` and put its verdict in INBOX verbatim: `G2 ≥ 60` **met/MISS**,
every category at 0 named; G1 must come out at **300** = `unknown` 120 · `ssh_brute_force` 115 ·
`suspicious_login` 25 · `privilege_escalation` 40 (DEC-086 — if it does not, the parameters or the
fold moved, and that is a finding, not a knob). Stage `eval/gold_candidates.csv`,
`eval/g1_clusters.csv`, `eval/g1_members.csv.gz`, `eval/gold_coverage.md`; the Owner commits. Open
`/admin/labels` once (needs P6-T02 merged): `total` = 300 + |G2|.

## 5 · 27/09 evening → 28/09 — κ, adjudication, freeze (needs P6-T03 merged)

You never touch a label. After both labellers finish: `label_export.py kappa` → paste κ (3 × 3);
`label_export.py disagreements` → the adjudication list for the meeting; the Owner + advisor fill
`final_label`/`final_note` in `eval/adjudication_v1.csv`; 28/09 `label_export.py freeze` →
`report`; stage `eval/gold_v1.csv`, `eval/gold_v1.sha256`, `docs/gold-v1-report.md`. That
commit — the Owner's — **is the P6 exit gate**. The G3 load (`eval/adversarial/load.py`) is
**29/09 and not earlier** (item (7)); do not run it because it is ready.

## 6 · Hard limits, in addition to owner-assist.md §5

- No `sudo`, no `docker` — hand them over. The one sudoers entry (`tail /data/wazuh/logs/ossec.log`,
  exact form only) is for reading the manager log.
- No label, no `reviewed_by`, no product code, no `STATE.md`, no `DECISIONS.md`, no `git push`,
  no commit outside `docs/plan/` unless the Owner says "commit it" for that file.
- Every number you report carries its command and its denominator; every INBOX entry is dated to
  the minute. A window you did not time to the second is a window that did not happen.
