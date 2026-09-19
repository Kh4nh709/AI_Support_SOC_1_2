# Planner P4 — addendum for a brief last swept on 14/09, read on 19/09

**Invocation (the Owner pastes this, nothing else — session name `planner-P4`):**

```
Read docs/plan/prompts/P4.md and act as that Planner. Before you write a single card, read
docs/plan/prompts/planner-run-P4-2026-09-19.md — it lists what changed after the brief was
last swept. Do everything the brief says, then give me the summary it asks for.
```

`prompts/P4.md` governs the phase. This addendum exists because the brief's sweep date is
**14/09 23:52** and it cites nothing after DEC-066; twenty-two decisions have landed since, and
five of them change what P4 must build or when. Written by the Support Agent at the Owner's
instruction; the Director may have swept the brief by the time you read this — if the brief
already says these things, this file is confirmation, not contradiction.

## 1 · Dates — the brief's title says 10/09, the plan says 18/09, and it is 19/09

DEC-071 re-dated P4 to **18/09**. A three-day host outage (16/09 08:02 → 19/09) ate DEC-071's
buffer. So P4 is late on the day it is planned, and **the order of its cards is not free**:
§3 below says which three must ship first and why.

## 2 · Decisions since the sweep that bind this phase

| decision | what it changes for P4 |
|---|---|
| **DEC-079** (15/09) | P2 is closed and **all of it is in `main`** — including the pieces the brief lists as "skeleton": `backend/app/web/main.py`, `web/worker.py`, `tier1/`, `domain/transitions.py`; `security/`, `llm/`, `kb/` exist from P3. **Read `main`, not the brief's 07/09 description of it**, before you scope any file |
| **DEC-082 / DEC-083** (15/09) | the inventory **is loaded** into `assets`/`identities`/`iocs` now (it was not on 15/09 morning), and the replayed corpus in `soc_dev` — `alerts`: `replay` 92,011 + `wazuh` 3,941 — **is what the pilot's queue shows**. It is **not** G1 (G1 is built offline from the archive fold, DEC-084). The queue and detail pages therefore render real replayed rows; card the fixtures against that shape |
| **DEC-085** (16/09) | lab alerts are retagged post-hoc to `source='lab'` by `eval/lab_tag.py`, **no schema change**. The visibility filter's `labeling` mode must strip `alerts.source` for **three** values now (`replay`, `wazuh`, `lab`) — the forbidden-substring test in the brief (DEC-019) gains `lab` |
| **DEC-086** (16/09) | G1 = 300 clusters + \|G2\|; `/api/admin/labels/*` is P6-T02's, **not yours**, but it sits under the `admin` role your T01 defines and the base layout your T04 provides — see §3 |
| **DEC-088** (16/09) | the 3-session cap holds; P6-T05 occupied one slot and P3's tail (T09→T10→T11) takes another. Assume **at most two P4 sessions at a time** when you estimate wall-clock |
| **DEC-065 / DEC-070** (14–15/09) | the indexer moved to `https://wazuh.indexer:19200`, `INDEXER_USER=soc_ro`. P4 does not touch it; do not let a card re-state any indexer value |
| **DEC-066** (already cited) | `HR-computer` and `wazuh.manager` are in `conf/inventory.yaml`; the pilot's live alerts are 79 % `HR-computer`. The queue will be dominated by SCA/EventChannel noise from a Windows endpoint — a fact for the pilot checklist (T07), not a reason to filter |

## 3 · The critical path runs through three of your cards — say so in the index

The blind labelling page is **P6-T02**, and its card (`tasks/P6/P6-T02.prompt.md:17,28`) depends on
**P4's auth, visibility filter and base layout**. Labelling is fixed at **26–27/09** by two people's
availability, which no schedule move can buy back. So:

- **P4-T01 (auth + seed CLI), P4-T02 (queue + visibility filter with `labeling` mode), P4-T04
  (base layout + login)** are the first wave and must be **mergeable by 21/09**. Write them with
  disjoint files so they run in parallel, and name them as P6-T02's prerequisites in the index.
- The seed CLI must create the advisor's `admin` account — P6 item (1) on the board — so T01's
  acceptance includes seeding an `admin` user and proving `/api/admin/*` is refused to `analyst`.
- T03 (decide/escalate/reopen), T05 (detail page), T06 (E2E), T07 (pilot checklist), T08 (webhook,
  P2-T12 re-homed with DEC-040's two keys) are the second wave. **T08 is `should`** and last.

## 4 · Two facts about the host you would otherwise get wrong

- **worker and puller are not running** since the 16/09 reboot; `alerts` has not grown since
  15/09. The pilot needs both up; that is an Owner action in T07's checklist, with the proof
  command (`select count(*) from alerts where source='wazuh'` rising; `source_cursor.last_sort`
  advancing).
- `/data/wazuh/logs/alerts/alerts.json` is unreadable by `user1` after the reboot. Nothing in P4
  reads it; do not card anything that does.

## 5 · What has not changed

Everything else in `P4.md`: §6.4 API, the optimistic lock, blind-branch suggestion stripping at
the API (never in the template), `tier1.decided` audit payload fields, HTMX from cdnjs pinned,
Jinja2 autoescape, no build step, the E5 checks the Director will run on your output
(`grep -l "{{"`, disjoint files, runnable acceptance lines, nothing from §11 assigned to an agent,
`must` estimates ≤ day budget × 1.3 or the overbooking note at the top, one `STATE.md` row per task
at `todo`).
