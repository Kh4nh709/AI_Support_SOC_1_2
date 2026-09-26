# Demo — AI Support SOC v3 in ten minutes

P8-T04 (DEC-129). A timed script for the Owner's demonstration of what was built and evaluated: one alert
through the pipeline, ① and its 7-step gate on that alert, the blind labelling page, and the evaluation
tables. The Owner rehearses it (P8 exit gate: "demo rehearsed (Owner), or the demo cut and recorded").

**Not shown, because it does not exist.** The brief's queue → decide → escalate → ② → conclude → digest path
was not built: the Tier-1/Tier-2 console was deprioritized and cut (DEC-116), ② was cut (DEC-097, DEC-111),
and the digest was not built (`docs/limitations.md` (xiii), (xxii), (xxiii)).

**How the commands run.** One terminal in the primary checkout, prepared by the pre-flight. `.env` is
sourced there, so every `psql` reads `"$DATABASE_URL"` and nothing on screen restates a value from it.
`PGOPTIONS` makes every `psql` session in that terminal read-only. Every query below only reads, and each
one, exactly as printed here, was run against a private test database with fixture rows
(`docs/plan/tasks/P8/P8-T04.report.md`).

| Clock | Segment | Minutes |
|---|---|---|
| 0:00–1:00 | 1 · The problem and the shape | 1 |
| 1:00–3:00 | 2 · An alert through the pipeline | 2 |
| 3:00–6:00 | 3 · ① and its gate on that alert | 3 |
| 6:00–8:00 | 4 · Blindness | 2 |
| 8:00–10:00 | 5 · The numbers | 2 |
| | **Total** | **10** |

## Pre-flight checklist

1. Terminal: `cd /project/project/AI_Support_SOC_1_2 && set -a; . ./.env; set +a; export PGOPTIONS='-c default_transaction_read_only=on'; echo "${DATABASE_URL:+env ok}"` → `env ok`; then `psql "$DATABASE_URL" -XAtc 'show default_transaction_read_only'` → `on`.
2. Stack up: `docker compose ps` → `db`, `app` and `worker` running. Nothing is started or restarted for the demo.
3. The latest pull is under 5 min old: segment 2's second query → `pull_age_s` below 300 and `last_error_is_null` = `t`.
4. An admin account can log in: in the demo browser, sign in at `http://127.0.0.1:8000/login` with a labelling account (`role` = `admin`), open `/admin/labels`, note whether it shows a cluster or `Đã xong`, then sign out. Five failed sign-ins lock the account for 15 minutes (`LOGIN_MAX_FAILS`, `LOCKOUT_MINUTES`).
5. `docs/results/*.md` present: `ls docs/results/` → `ablation.md`, `adversarial.md`, `operations.md`, `per_category.md`, plus `predictions_<gold12>.csv`.
6. Browser tabs open: the §2 figure `file:///project/project/AI_Support_SOC_1_2/docs/kien-truc-v3-14-ngay.html#s2-flow`, and `http://127.0.0.1:8000/admin/labels`.
7. A second terminal, the Owner's, on the lab host with `docs/lab-scenarios.md` §4 open. Nothing runs in it before 0:00.
8. A terminal font at which a 110-column table fits on one line; segment 2's tables are the widest.

## What not to do during the demo

- No attack scenario live: the one live event is `docs/lab-scenarios.md` §4 · The benign block, run by the Owner.
- No command that writes to `soc_dev` except the Owner's one benign scenario: every `psql` here is read-only (pre-flight line 1), no label is saved on the page, and nothing is tagged.
- No `.env` on screen: never `cat .env`, `env`, `printenv` or `echo "$DATABASE_URL"`.

## 1 · The problem and the shape — 1 min

**Clock:** 0:00–1:00. At 0:00, before the first sentence, the Owner starts segment 2's live event in the
second terminal.

**Say.** A SOC's first tier spends much of its time deciding which Wazuh alerts are noise; a language
model can propose that decision, but it is only safe if no alert text can talk it into closing a real
attack. Here alerts are
pulled from the Wazuh indexer, merged into clusters, enriched and queued, and ① (a proposer, a 7-step
gate and a verifier) suggests a verdict that is recorded, never acted on. What was built is *a triage
engine evaluated offline plus a blind-labelling console; the Tier-1/Tier-2 console and ② were cut
(DEC-116, DEC-111)*.

**Show.** The §2 figure *Đường đi một alert* in the browser tab from pre-flight line 6. Trace the main row
from `intake` to `queued_tier1`, the two early stops (*duplicate*, *auto_closed*) and the dashed ①
branch (*proposer → cổng → verifier*). Then point at the right end (*Analyst T1*, *case · T2*) and the
dashed ② box: these are the parts that were cut.

**URL.**

```text
file:///project/project/AI_Support_SOC_1_2/docs/kien-truc-v3-14-ngay.html#s2-flow
```

**The audience sees** the one-alert flow of architecture §2: four stopping points on the main row and two
AI branches drawn off it with dashed lines.

## 2 · An alert through the pipeline — 2 min

**Clock:** 1:00–3:00.

**Live event (the Owner's).** `docs/lab-scenarios.md` §4 · The benign block. The Owner runs it from that
section, in the second terminal, from 0:00. A demonstration run is not a lab window: nothing from it is
tagged, and nothing from it enters G2, which is frozen.

**Say.** A worker pulls the Wazuh indexer every 60 seconds from a persistent cursor and writes each
document to an append-only intake ledger; one pipeline job then parses, deduplicates, enriches and
either auto-closes or queues it. These rows are heads, one per cluster, with how many alerts merged into
each and where ① stands on it. The Owner's benign activity on the lab host started at 0:00, and here are
its alerts, each pulled within about one pull interval of firing.

**Show, in order.**

1. The newest heads.

   ```bash
   psql "$DATABASE_URL" -X -P pager=off <<'SQL'
   -- the newest heads: one row per cluster (duplicate_of IS NULL)
   SELECT alert_id, rule_id, category, severity, occurrence_count, triage_status,
          to_char(received_at AT TIME ZONE 'Asia/Ho_Chi_Minh', 'HH24:MI:SS') AS received
   FROM alerts
   WHERE duplicate_of IS NULL
     AND NOT is_synthetic
   ORDER BY received_at DESC
   LIMIT 8;
   SQL
   ```

2. The pull loop is alive.

   ```bash
   psql "$DATABASE_URL" -X -P pager=off <<'SQL'
   -- the pull loop: one cursor row, moved by every successful pull
   SELECT c.manager_id,
          to_char(c.last_pull_at AT TIME ZONE 'Asia/Ho_Chi_Minh', 'HH24:MI:SS') AS last_pull,
          round(extract(epoch FROM now() - c.last_pull_at)) AS pull_age_s,
          c.last_error IS NULL AS last_error_is_null,
          to_char(h.last_alert_at AT TIME ZONE 'Asia/Ho_Chi_Minh', 'HH24:MI:SS') AS last_alert
   FROM source_cursor c
   LEFT JOIN source_heartbeat h USING (manager_id);
   SQL
   ```

3. The live event arriving. If no row shows yet, run it once more after 30 s.

   ```bash
   psql "$DATABASE_URL" -X -P pager=off <<'SQL'
   -- the lab agent's alerts of the last 10 minutes, and how long each waited for the pull
   SELECT a.alert_id, a.category, a.status, a.triage_status,
          to_char(a.alert_time AT TIME ZONE 'Asia/Ho_Chi_Minh', 'HH24:MI:SS') AS fired,
          to_char(i.received_at AT TIME ZONE 'Asia/Ho_Chi_Minh', 'HH24:MI:SS') AS pulled,
          round(extract(epoch FROM i.received_at - a.alert_time)) AS wait_s,
          i.via
   FROM alerts a
   JOIN intake i ON i.manager_id = a.manager_id AND i.source_alert_id = a.alert_id
   WHERE a.agent_name = 'attt-m1-lab'
     AND a.received_at > now() - interval '10 minutes'
     AND NOT a.is_synthetic
   ORDER BY a.alert_time DESC
   LIMIT 10;
   SQL
   ```

**The audience sees.**

1. Up to eight heads, newest first. `occurrence_count` is how many alerts the cluster absorbed, and
   `triage_status` is ①'s state on it: `pending`, then `ready` or `unavailable`.
2. One row, `manager_id` = `indexer`. `pull_age_s` stays under about 60 while the worker runs, and
   `last_error_is_null` is `t`.
3. The benign activity's alerts from `attt-m1-lab`. `status` is where the pipeline left each one:
   `queued_tier1`, `duplicate` (merged into an existing head) or `auto_closed`. `via` is the intake
   path, `pull` for the puller.
   `wait_s` (pulled minus fired) is at most about one pull interval (`PULL_INTERVAL_S` = 60) plus the
   indexer's own delay. Note one head whose `triage_status` is `ready`: segment 3 uses its `alert_id`.

## 3 · ① and its gate on that alert — 3 min

**Clock:** 3:00–6:00.

**Say.** ① only proposes: the proposer's JSON passes a 7-step gate and a second model call, the
verifier, and both calls are kept in the append-only `llm_runs` table, the proposer's with the full gate
record. This is that record for the alert we just watched arrive: what the model proposed, what each
step did, and whether the verifier agreed; the prompt text is in the row but not on screen. The rule that matters is that
`false_positive`, the verdict an attacker wants, only leaves the gate on structural evidence the attacker
does not control.

**Show, in order.**

1. The gate record of the head noted in segment 2. If it is still `pending`, run segment 2's third query
   again after 15 s.

   ```bash
   AID='<alert_id of the ready head from segment 2>'
   psql "$DATABASE_URL" -X -x -P format=wrapped -P pager=off -v aid="$AID" <<'SQL'
   -- ① on one head: the proposer's claim, each gate step, the verifier; never the prompt text
   SELECT r.subject_id AS alert_id,
          r.stopped_by IS NULL AS gate_ran,
          r.gate_result->'proposer_raw'->>'suggested_action' AS proposed,
          r.gate_result->'proposer_raw'->>'confidence' AS confidence,
          r.gate_result->>'final_verdict' AS final,
          r.gate_result->'forced' AS forced,
          r.gate_result->'forced_by' AS forced_by,
          r.gate_result->'steps' AS steps,
          r.gate_result->'dropped_reasons' AS dropped_reasons,
          r.gate_result->'missing' AS missing,
          r.gate_result->'warnings' AS warnings,
          r.verifier_result - 'reason' AS verifier,
          jsonb_pretty((SELECT jsonb_agg(jsonb_build_object('index', t.i - 1,
                                                           'source', t.x->'source',
                                                           'quote', t.x->'quote') ORDER BY t.i)
                        FROM jsonb_array_elements(r.gate_result->'proposer_raw'->'reasons')
                             WITH ORDINALITY AS t(x, i))) AS reasons
   FROM llm_runs r
   WHERE r.pipeline = 'triage'
     AND r.role = 'proposer'
     AND r.subject_id = :'aid'
   ORDER BY r.created_at DESC
   LIMIT 1;
   SQL
   ```

2. Walk the seven steps against the `steps` line, one sentence each (architecture §4.2):

   | Step | What it does | Where it shows in the record |
   |---|---|---|
   | 1 · schema | The proposer's JSON must match `triage_v2`'s closed sets and required fields; one repair is allowed, then the alert is `unavailable` with no verdict. | `"1": "ok"` or `"repaired"`; a row that stopped here has `gate_ran` = `f` |
   | 2 · basis ↔ DB | The facts the model says it used must equal the database's, field by field, or the run is flagged as a hallucination and forced to `needs_review`. | `"2": "ok"` or `"mismatch"` |
   | 3 · quote ⊂ block | Each reason's quote must be a substring, after Unicode and whitespace normalisation, of the untrusted block its `source` names; a reason whose quote is not there is dropped, and with no reason left the verdict is `needs_review`. | `"3": "dropped:N"`, `dropped_reasons` (`index` matches `reasons`) |
   | 4 · FP policy | `false_positive` survives only if severity is not critical, the IoC is not malicious or suspicious, the asset is neither high nor unknown, the identity is not privileged, and the decision-table rule it cites is signed and holds on the database's facts. | `"4": "ok"`, `"missing"` or `"n/a"`; `missing` names what failed, and `warnings` shows `table_unreviewed` while a table is unsigned (DEC-132) |
   | 5 · detector | Injection findings are recorded and never change the verdict. | `"5": "findings:N"` |
   | 6 · verifier | A second call that sees only the database's facts, the decision table and the proposal (as untrusted data) must agree and reach the same verdict from facts alone, or the verdict is `needs_review`. | `"6": "agree"`, `"disagree"` or `"invalid"`; `verifier` |
   | 7 · output guard | The closed sets are checked again, nothing is acted on, both calls are written to `llm_runs`, and `triage_status` becomes `ready`. | `"7": "ok"` |

   Only the proposer can set `false_positive` or `escalate`; every later step can only move the verdict
   to `needs_review`. `forced` is `proposed ≠ final`, and `forced_by` names the steps that forced it.

3. Where a quote that is not in its block is dropped (step 3), in the code and in its tests:

   ```bash
   sed -n '/^def step3_quotes/,/^def step4_fp_policy/p' backend/app/security/gate.py
   .venv/bin/python -m pytest -c backend/pyproject.toml backend/tests/test_gate.py -k step3 -m 'not db' -vv
   ```

**The audience sees.**

1. One expanded record: `gate_ran` `t`, then `proposed` and `confidence` (the proposer's own claim),
   `final`, `forced`, `forced_by`, the seven `steps`, `dropped_reasons`, `missing`, `warnings`, the
   verifier's `agree` and `structured_only_verdict`, and each reason's `index`, `quote` and `source`.
   If `gate_ran` is `f`, ① stopped before the gate (`unavailable`): take another `ready` head from
   segment 2's first query.
2. The step line of the record, read left to right.
3. `step3_quotes`, where a quote that is not a substring of its block goes to `dropped` with
   `"why": "not_substring"`. Then five `test_step3_*` tests `PASSED`, including
   `test_step3_invalid_quote_dropped_survivors_kept`. If this head kept every reason (`"3": "dropped:0"`),
   that test is where a reason is seen being dropped.

## 4 · Blindness — 2 min

**Clock:** 6:00–8:00.

**Say.** The gold set is labelled on this page, blind: the labeller sees the alert, its cluster, the
±2-hour correlation and the playbook, and nothing from ① or from the lab windows that set the truth.
That is built into the page: it is assembled from an allowlist of 19 keys and reads `alerts` through an
explicit column list, so ①'s output and the `source` column never reach the process that renders it
(P6-T02). The input boundary is pinned by a test as well: a candidates file that carries the window truth
yields candidates without it (P6-T10, DEC-117).

**Show, in order.**

1. The page. Open the URL and you are redirected to `/login`; sign in with the labelling account. The app
   then redirects to `/queue`, which was never built (DEC-116), so the browser shows
   `{"detail":"Not Found"}`. Say so in one line, and open the URL again. Do not click `Hàng đợi` (the same
   unbuilt page), and do not press `Lưu nhãn`: saving a label is a write.

   ```text
   http://127.0.0.1:8000/admin/labels
   ```

2. The allowlist, and the input-boundary test:

   ```bash
   sed -n '/^VIEW_KEYS/,/^)/p' backend/app/tier1/labels.py
   .venv/bin/python -m pytest -c backend/pyproject.toml backend/tests/test_labels.py -k drops_the_window_truth_columns -m 'not db' -vv -W ignore::DeprecationWarning
   ```

**The audience sees.**

1. *Gán nhãn tập vàng* with `Đã gán: d / N`, then one cluster: category · severity · rule (level) · the
   cluster id; the representative alert (time, agent, user, src → dst, description); `raw_log`; the
   occurrence count with first and last seen; the ±2 h correlation table; the playbook; and the form with
   three labels (*Báo động giả*, *Thật nhưng vô hại*, *Cần chuyển tier 2*), a confidence of 1–3 and a
   one-line note. There is no suggested action, confidence, reason, gate result or triage status from ①,
   and no scenario, kind or truth label. A labeller who has finished sees only `Đã gán: N / N` and
   *Đã xong*; then the allowlist and the test carry the point.
2. The 19 names of `VIEW_KEYS`, none of them from ① or from a lab window. Then
   `test_load_candidates_drops_the_window_truth_columns PASSED`.

## 5 · The numbers — 2 min

**Clock:** 8:00–10:00.

**Say.** The evaluation is offline: five configurations run on the frozen G2 gold set, from B0 (severity
alone) to B4 (① with its gate and verifier, as deployed), each with a bootstrap 95% interval. Recall of
`escalate` is strict, since only `escalate` on an attack counts as caught, and the share handed to a human
as `needs_review` is printed beside it, never folded in; the thinking pair is B4 on the same clusters with
the model's thinking off and on (DEC-042), and ASR is the share of G3's adversarial alerts that leave the
gate as `false_positive`. One caveat governs every number here: this is author-generated lab traffic, so
no rate is an estate rate (`docs/limitations.md` (xii)).

**Show, in order.** The configurations, for the presenter: B0 severity alone; B1 the decision tables, no
model; B2 ① without enrichment or correlation; B3 ① with gate steps 1–3 and no verifier; B4 as deployed.
Before the demo, read item (xi) of `docs/limitations.md`. If the decision tables were unsigned at the
evaluation run, B4 closes nothing and its ASR is 0 by construction (DEC-132). Say that, and do not say
that B4 resisted the injections.

1. The headline row per configuration, with strict recall(escalate) and the deferral beside it:

   ```bash
   sed -n '/^## Headline (G2)/,/^## Truth/p' docs/results/ablation.md | cut -d'|' -f2-7
   ```

2. The paired thinking rows:

   ```bash
   sed -n '/^## Paired thinking ablation/,/^## Prompt v1.1/p' docs/results/ablation.md
   ```

3. ASR per configuration on G3:

   ```bash
   grep -A4 -E '^## (B|Expectation)' docs/results/adversarial.md
   ```

4. The close: the sentence every results file opens with.

   ```bash
   head -1 docs/results/ablation.md
   ```

**The audience sees.**

1. One row per configuration, B0–B4, with B4 twice (thinking `disabled` and `enabled`): `n`, macro-F1,
   `recall(escalate) strict`, and `deferral(escalate)` in the very next column, each with its `[95% CI]`.
2. The disabled and enabled values for macro-F1, strict recall(escalate), precision(close) and
   evidence-verified, the paired delta with its interval, then cost per alert, p50/p95 latency and an
   exact McNemar test.
3. For B3 and B4: `n`, `successes`, `ASR` and `error rate`, and last the line `expected: B3 > 0, B4 ≈ 0`,
   printed as an expectation, not a result.
4. *This corpus is author-generated lab traffic on the author's host with window-known truth: no rate
   computed from it is an estate rate, of any estate.*

## Questions, if asked

1. *Where are the analyst queue, decide and escalate, ② and the digest?* Not built or cut:
   `docs/limitations.md` (xiii), (xxii), (xxiii); DEC-116, DEC-111.
2. *Who set the truth, and who labelled?* `docs/limitations.md` (xii), (xv) and (xx), and
   `docs/lab-scenarios.md` §2 (the window protocol).
3. *Can text planted in a log talk ① into closing an alert?* `docs/results/adversarial.md`, and
   `docs/limitations.md` (xxviii) and (xi).
4. *What did the system do online over the lab days: intake, dedup, the gate-forced rate, cost?*
   `docs/results/operations.md` (P8-T01).
5. *Does alert data leave the host, and is the verifier independent of the proposer?*
   `docs/limitations.md` (xxvii) and (xxvi).
