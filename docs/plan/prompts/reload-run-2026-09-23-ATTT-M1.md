# Nạp lại context sau khi chuyển máy — mọi vai, 23/09/2026 (host ATTT-M1)

Viết sau DEC-106 (chuyển IA1803 → ATTT-M1, 22/09). Mỗi mục dưới đây là **một khối dán độc lập**: mở
đúng thư mục, `claude` → `/resume` phiên của vai đó, rồi dán nguyên khối. Không cần dán gì thêm.

Còn **9 ngày** đến hạn 02/10 (DEC-071). Lịch còn lại: P4 code → P6-T02 → **gán nhãn 26–27/09** →
**đóng băng gold 28/09** → P7 29/09 → P8 30/09–01/10 → nộp 02/10.

**Thư mục mở phiên:** Director / Planner / Reviewer / Owner Assist / KB Drafter / Detection Author →
`/project/project/AI_Support_SOC_1_2`. Coder → worktree `../AI_Support_SOC_1_2-<TASK_ID>`. Phiên trợ
giúp hạ tầng → `/project/project`.

---

## §0 · Sự thật về host mới (đã nằm trong mọi khối dưới, ghi lại đây để người đọc đối chiếu)

| Thứ | Giá trị trên ATTT-M1 | Ghi ở |
|---|---|---|
| Đường dẫn repo | `/project/project/AI_Support_SOC_1_2` (không đổi) | DEC-106 |
| `make` | **luôn** `make <target> PY=.venv/bin/python` — `python3` của máy là 3.14 không có pytest/ruff | DEC-106 |
| Số xanh | lint sạch · `test` **1042 passed, 1 skipped, 549 deselected, 2 xfailed** · `test-db` **549 passed** | DEC-106 |
| CSDL | container `127.0.0.1:55432`, DSN đọc từ `.env` | DEC-105 |
| Worker | `make run-worker` để bật · `docker compose restart worker` sau merge chạm `web/worker.py`, `soar/`, `infra/puller.py` | DEC-105 |
| Indexer | **stack Wazuh của chính máy này**, `INDEXER_HOST_IP` **để trống** · `/etc/hosts` **chưa có** `wazuh.indexer` → probe phía host chết, phải đi qua container | DEC-106 |
| Worktree đang mở | P3-T11 · P4-T03 · P4-T04 · P4-T08 · P6-T06 (tất cả **cũ hơn** `5b1deb1` → `git merge main` trước) | DEC-106 |
| DEC cuối | **DEC-106** | — |

---

## 1 · Director

```
Host moved to ATTT-M1 on 22/09 (DEC-106 — read it first, it is the last entry in DECISIONS.md).
Repo at the same path; restored from ~/soc-backup/2026-09-21; counts matched on five figures;
worker running and caught up. Today is 23/09; the deadline is 02/10 (DEC-071).

Standing prompt is unchanged: prompts/director.md. Four host facts that change how you verify:
1. Every make target needs PY=.venv/bin/python — this host's python3 is 3.14 with no pytest/ruff.
   Green as of 22/09: lint clean, test 1042 passed / 1 skipped / 549 deselected / 2 xfailed,
   test-db 549 passed. A bare `make test` failing on "No module named pytest" is the environment,
   not a red suite.
2. The database is the container on 127.0.0.1:55432; DSNs come from .env (DEC-105). The native
   cluster does not exist on this host at all, so socket DSNs now fail loudly rather than silently.
3. The indexer is THIS box's own Wazuh stack, not IA1803's. INDEXER_HOST_IP must stay unset.
   /etc/hosts has no wazuh.indexer line yet, so eval/indexer_probe.py and eval/smoke_test.py fail
   with ConnectError on the host; reach the indexer with
   `docker compose exec -T worker python -c ...`. The account is soc_ro / role soc_ro_role, read
   only on wazuh-alerts-*; _cat/indices returns 403, so indexer_probe stays broken until the role
   is widened. Do not read that 403 as a broken host.
4. All five open worktrees predate 5b1deb1, so DEC-105 is unchanged: each Coder session runs
   `git merge main` first and derives TDB from the primary checkout's .env.

Board state to reconcile against git, not against memory:
- P0–P3 done (P3 closed 20/09, gate 4/4). P6 in-progress. P4, P5, P7, P8 todo.
- P4: T01, T02, T07 done. T03, T04, T05, T06, T08 todo. Worktrees exist for T03, T04, T08.
- P6: T01, T03, T04, T05 done. T02 todo (depends on P4-T01/T02/T04). T06 todo, worktree exists.
- P3-T11 todo, worktree exists; it needs the Owner to run the live test with a real key.
- The bottleneck is P4-T04: both P4-T05 and P6-T02 wait on it, and P6-T02 is the blind labelling
  page that 26–27/09 labelling cannot happen without.
- DEC-097 is armed and you apply it without asking: if at the end of 25/09 either half is false —
  (i) P6-T02 merged into main, (ii) eval/gold_candidates.csv built by the 25/09 build_gold.py
  --g1 --g2 run — then ② falls automatically in §10 order. Both true → ② gets one agent-day on
  28/09, after the DEC-032 measurement at its own prompt size.

Four Owner actions are open in STATE.md and none of them is yours to do: add Windows_Endpoint to
conf/inventory.yaml (it is 1,186 of 1,372 live alerts and absent from the inventory — DEC-066's
case, G8′ pins needs_review on 86% of the live stream); the /etc/hosts line; the decision on how
make runs on this host (three options, all in the row); and confirming IA1803 is down when a
network path exists — until then it stays recorded as presumed, not verified.

Two facts about the data you will need when you read numbers: the live stream has a 38 h 41 m hole
(20/09 17:00:11Z → 22/09 07:41:28Z, 0 rows, unrecoverable — IA1803 unreachable and its retention
is 4 days per DEC-017), and G1 is untouched by it (frozen 08/08–07/09, replay byte-identical at
92,011 rows), so no evaluation is invalidated.

Do the morning run: reconcile STATE.md with git, resolve every open INBOX item, merge what is
approved, dispatch by creating worktrees before naming tasks (DEC-045), then print Owner actions,
Dispatch now, Decisions taken and Risks with the date each one bites.
```

---

## 2 · Planner

```
Host moved to ATTT-M1 on 22/09 (DEC-106); repo at the same path. Today is 23/09, deadline 02/10
(DEC-071). Every make target on this host needs PY=.venv/bin/python (python3 is 3.14 without
pytest/ruff); the database is the container on 127.0.0.1:55432 with DSNs from .env (DEC-105).

Phases already planned: P0–P4 and P6 have cards in docs/plan/tasks/. Not yet planned: P5, P7, P8.

If you are being run for a phase brief, read prompts/P<n>.md and produce tasks/P<n>/P<n>-tasks.md
plus one <TASK_ID>.prompt.md per task from prompts/coder-template.md, with one STATE.md row per
task at status todo. Three things the template now carries that a pre-22/09 brief does not:
- the Acceptance preamble that derives TDB from the primary checkout's .env (DEC-105) — never a
  socket DSN, never the shared soc_test;
- PY=.venv/bin/python on every make line in an acceptance command;
- no card may require reaching the indexer from the host: /etc/hosts has no wazuh.indexer line, so
  an indexer command in a card runs inside the worker container or not at all (DEC-106).

If you are being run for P5, read DEC-097 before writing anything: ② (D11) is conditional until
the end of 25/09 and may fall automatically, so its cards must be separable from the rest of P5
rather than woven through it. DEC-032's measurement at CASE_PROMPT_BUDGET_TOKENS=60_000 precedes
any ② work.

E5 self-check before you hand over, as always: every acceptance item is a command, file lists are
disjoint from every open card (P3-T11, P4-T03, P4-T04, P4-T05, P4-T06, P4-T08, P6-T02, P6-T06),
sum of `must` estimates ≤ day budget × 1.3, one STATE.md row per task, index entry present.
```

---

## 3 · Coder — một khối cho mỗi worktree đang mở

Dán trong `../AI_Support_SOC_1_2-<TASK_ID>` sau `/resume`. Thay `<TASK_ID>` bằng một trong
**P3-T11 · P4-T03 · P4-T04 · P4-T08 · P6-T06**.

```
Host moved to ATTT-M1 on 22/09 (DEC-106). This worktree is at the same path as before and your
branch is untouched, but it predates 5b1deb1, so before anything else:

    git merge main

That brings in the compose Makefile and scripts/dsn_env.py. Then re-read your card — its
Acceptance section has a "Database since 20/09" preamble that replaced the old
postgresql:///soc_<task>_test socket DSN (DEC-105):

    TDB="$(sed -n 's/^TEST_DATABASE_URL=//p' ../AI_Support_SOC_1_2/.env | sed 's|/soc_test$|/soc_<task>_test|')"
    eval "$(python3 ../AI_Support_SOC_1_2/scripts/dsn_env.py "$TDB")"

Two things are new on this host and both will look like a defect if you do not know them:
1. Every make target needs PY=.venv/bin/python. This box's python3 is 3.14 with no pytest and no
   ruff, so a bare `make test` dies at "No module named pytest" — environment, not a red test.
   Reference green: lint clean, test 1042 passed / 1 skipped / 549 deselected / 2 xfailed,
   test-db 549 passed.
2. Before `make test-db`, check `ps aux` for another session's run. Two sessions sharing soc_test
   produce a false red (DEC-104) — that is why your card names a private database.

If your card needs the indexer: it is this box's own Wazuh stack now, reachable only from inside
the container (`docker compose exec -T worker python -c ...`) because /etc/hosts has no
wazuh.indexer line, and the read-only account is denied _cat/indices (DEC-106).

Continue your task. When code and tests are green, write tasks/P<n>/<TASK_ID>.report.md and set
your STATE.md row to review, exactly as your card says.
```

**Ghi chú riêng từng card, dán thêm một dòng:**

- **P3-T11** — `test_triage_live.py` + `eval/triage_live.py` + xoá thư mục `llm/` ở gốc. *"The
  live half needs the Owner to run it with a real key from the primary checkout; build the harness
  so that run is one command, and do not block on the key."*
- **P4-T03** — `tier1/decide.py` + `web/routers/tier1.py`. *"P4-T05 and P4-T06 are both waiting on
  you and on P4-T04; you two are the critical path to the 26–27/09 labelling."*
- **P4-T04** — `web/templating.py` + `templates/` + `web/routers/pages.py`. *"You are the
  bottleneck of the whole schedule: P4-T05 and P6-T02 both depend on you, and P6-T02 is the blind
  labelling page that 26–27/09 cannot start without. Deliberately small — keep it small."*
- **P4-T08** — `infra/intake.py` + `web/routers/webhook.py`. *"Both keys stay empty on this host,
  so the route returns 503; that is the expected acceptance state (DEC-040)."*
- **P6-T06** — câu DEC-086 trong `eval/gold_coverage.md`. *"≤ 0.5 h, three files disjoint from
  every other open card; finish it in one sitting."*

---

## 4 · Reviewer

```
Host moved to ATTT-M1 on 22/09 (DEC-106); repo at the same path, standing prompt unchanged
(prompts/reviewer.md). Today is 23/09.

Three things change how you verify, and all three can make a good card look red:
1. Every make target needs PY=.venv/bin/python — this host's python3 is 3.14 with no pytest or
   ruff. Reference green on main as of 22/09: lint clean, test 1042 passed / 1 skipped /
   549 deselected / 2 xfailed, test-db 549 passed. "No module named pytest" is the environment.
2. Test DSNs are TCP and come from .env (DEC-105): prompts/reviewer.md:12 carries the form. The
   native cluster does not exist on this host, so any socket DSN you meet in an old card or an old
   report is dead — a report that claims green through postgresql:///… was measured on the old
   host, and you should say so rather than re-run it here.
3. An acceptance command that reaches the indexer from the host cannot pass: /etc/hosts has no
   wazuh.indexer line and the read-only account is denied _cat/indices (DEC-106). Run it inside
   the worker container, or record it as not executable on this host — never report a gate met on
   a path you did not execute.

Run the acceptance commands yourself in a clean checkout, write
tasks/P<n>/<TASK_ID>.review.md with APPROVE or CHANGES, and set the review cell in STATE.md. Open
cards you may be asked about: P3-T11, P4-T03, P4-T04, P4-T05, P4-T06, P4-T08, P6-T02, P6-T06.
```

---

## 5 · Owner Assist

```
The worker now runs on ATTT-M1; re-arm your watch on container ai_support_soc_1_2-worker-1 here
(DEC-106). Your prompt is unchanged: prompts/owner-assist-P6-run-2026-09-19.md, §0 already carries
the compose form.

State as measured 22/09 20:2x: alerts 100,362 (replay 92,011 + wazuh 8,351), llm_runs 1,061,
jobs 102,418, audit_events 102,191, schema_migrations 17. source_cursor last_sort
1790083457507 = the newest document in the indexer, last_error null, heartbeat age 30 s, worker log
steady at {"hits": 1, "new": 0, "duplicates": 1}.

Your three proofs are unchanged and still DB-side only (you cannot see containers): cursor
advancing, heartbeat age, last_error empty, no failed jobs, a 172.x client present. The DSN is the
container's, from .env, on 127.0.0.1:55432. Any make command you are asked to run needs
PY=.venv/bin/python on this host — python3 here is 3.14 without pytest or ruff.

Two facts about the alert stream so you do not report them as faults:
- There is a 38 h 41 m hole, 20/09 17:00:11Z → 22/09 07:41:28Z, 0 rows. The source stack changed;
  it is not a puller failure and it cannot be backfilled (DEC-106).
- The indexer is this box's own Wazuh stack. Only two agents report: Windows_Endpoint (1,186 of
  1,372) and wazuh.manager (186). Windows_Endpoint is absent from conf/inventory.yaml, so G8′ pins
  needs_review on 86% of the live stream until the Owner adds it — already on the Owner actions
  list, do not fix it yourself.

Continue the P6 week's mechanical items and report as usual through INBOX.md.
```

---

## 6 · KB Drafter

```
Host moved to ATTT-M1 on 22/09 (DEC-106); repo at the same path, your work is intact. Today is
23/09. Your prompt is prompts/kb-drafter-run-2026-09-19.md.

Where things stand: the ten decision tables are drafted, and the signing-sitting pack is committed
at bddae6e — docs/kb-sitting/{agenda,invite,pre-read,open-questions,signing-checklist}.md. The
sitting has no date yet; the Director asked the Owner to put one on the board.

Nothing about the KB depends on the host move: kb/decision_tables/ and kb/playbooks/ are plain
files in the repo and kb/lookup.py reads them through KB_ROOT, bind-mounted read-only into the
container. If you run anything: make targets need PY=.venv/bin/python on this host.

One fact from the move that touches content, not process: the live estate changed. HR-computer,
DC01, kali and user1-IA1803 have all stopped reporting; the only live agents now are
Windows_Endpoint (1,186 of 1,372 alerts) and wazuh.manager. If any decision table or playbook
names a host as an example, check it is still a host that exists (DEC-106).

Continue: fold the review-sheet findings into the tables, and keep open-questions.md as the single
list the Owner and the advisor walk through at the sitting.
```

---

## 7 · Detection Author (vai một lần, mở 08/09)

```
Host moved to ATTT-M1 on 22/09 (DEC-106); repo at the same path. Your prompt is
prompts/detection-author.md. Today is 23/09; the lab week is 22–25/09 with labelling 26–27/09.

The one thing you must know before writing or checking a rule: the Wazuh stack is no longer
IA1803's. This box runs its own manager, indexer and dashboard (containers
single-node-wazuh.{manager,indexer,dashboard}-1), and none of IA1803's history came across — this
stack's alert history begins 22/09 07:41Z. IA1803's manager, its rules and its client.keys are
still on the old box and unreachable from here. So:
- Any rule you authored on IA1803 that is not in this repo is not on this stack. Check
  docs/wazuh-manager-changes.md against the live manager before assuming a rule is deployed.
- The four agents you wrote scenarios for (HR-computer, DC01, kali, user1-IA1803) are gone. The
  live agents are Windows_Endpoint (1,186 of 1,372 alerts) and wazuh.manager. Scenarios that
  assume a Linux agent or a Kali attacker host have no host to run on until the Owner enrols one.
- Windows_Endpoint is absent from conf/inventory.yaml, so every alert from it enriches to
  needs_review (G8′, DEC-066). That is on the Owner's list; write scenarios knowing it.
- Reach the indexer from inside the container only (docker compose exec -T worker python -c ...):
  /etc/hosts has no wazuh.indexer line and the read-only account is denied _cat/indices.

docs/lab-scenarios.md and docs/lab-run-log.md are the two files you own. Any scenario recorded as
run on IA1803 between 20/09 17:00Z and 22/09 07:41Z has no alert rows on this host and never will
(the 38 h 41 m gap) — mark those, do not re-date them.
```

---

## 8 · Phiên trợ giúp hạ tầng (backup / migration)

Mở ở `/project/project`, không phải trong repo.

```
The move you planned is done: host is ATTT-M1 since 22/09, repo at the same path, restored from
~/soc-backup/2026-09-21. Your runbook ran, and DEC-106 records where reality diverged from it —
read that DEC, then docs/migration-runbook.md, which I corrected in five places from it:
the header (đợt 1's premise broke), §3.3 (INDEXER_HOST_IP must stay UNSET when the indexer is
local; the /etc/hosts line is mandatory), §3.4 (source .env BEFORE make migrate), §5 (now 9 items,
with the PY=.venv/bin/python trap and the worktrees.txt comparison), §7 (the search_after
high-water-mark rule and the two new paragraphs on data and inventory).

Verified on the new host: five restore counts match counts-before.txt exactly; migrations 17;
make migrate "0 applied, 17 already present"; lint clean; test 1042 passed / 1 skipped /
549 deselected / 2 xfailed; test-db 549 passed (all three with PY=.venv/bin/python); login 401;
worker steady; 1,372 indexer docs = 1,372 new alerts rows, nothing skipped.

Three things still open that are yours to think about, not the Director's:
1. đợt 2 is untouched — IA1803's manager, client.keys, four agents and indexer volume are all
   still there. This box standing up its own stack did not move them. If đợt 2 is ever run, §7's
   new cursor rule applies and the 4-day retention (DEC-017) sets the clock.
2. There is no network path from here to IA1803 (no tailscale, no route), so "old host's compose is
   down" stays recorded as presumed, not verified. The exposure if it is wrong is a divergent
   second copy, not corruption — the hosts share no database and no indexer.
3. backups/latest.dump changed (32,566,681 → 32,978,015 bytes) because §3.4 says to copy the newer
   dump in; Makefile, README.md and docker-compose.yml show modified with mode-only changes
   (644 → 755) from the attt → user1 ownership fix. Neither is work in progress.

No backup set has been taken on this host yet. ~/soc-backup/backup-full.sh came across but its
paths and the wazuh/ half now describe a different stack — that is the next thing worth your turn.
```

---

## 9 · Owner (chủ đồ án — người, không phải phiên agent)

Bốn việc đang mở trong `STATE.md`, xếp theo mức chặn:

1. **`Windows_Endpoint` vào `conf/inventory.yaml`** — chặn chất lượng của 86 % luồng sống, và chặn
   sản lượng auto-close của pilot P4. Kiểm:
   `.venv/bin/python -c "import sys;sys.path.insert(0,'backend');from app.enrichment.inventory import validate;print(validate() or 'OK')"`
2. **Chọn cách chạy `make`** trên máy này (A: dán `PY=.venv/bin/python` — khuyến nghị · B: cài
   pytest/ruff cho `python3` hệ thống · C: đổi mặc định trong `Makefile`). Director không tự chọn.
3. **Một dòng `/etc/hosts`: `127.0.0.1  wazuh.indexer`** (cần root) — mở lại nửa host của probe.
4. **Xác nhận IA1803 đã xuống** khi có đường mạng; tới lúc đó ghi là *chưa kiểm*.

Ngoài ra: mở phiên Coder cho **P4-T04** trước hết (nút cổ chai), và **P3-T11** cần chủ đồ án chạy
live test bằng khoá thật từ checkout chính.
