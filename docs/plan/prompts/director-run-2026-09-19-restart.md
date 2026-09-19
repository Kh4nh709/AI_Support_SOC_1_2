# Director — restart run after the 16–19/09 outage: reconcile, re-arm the trigger, re-plan the week

**Invocation (the Owner pastes this, nothing else):**

```
Read docs/plan/prompts/director-optimized.md and act as the Director. Then read
docs/plan/prompts/director-run-2026-09-19-restart.md and execute it in order — a result-intake
run (DEC-048 batching) that ends in an evening-gate row, and it must also write the gate rows
the outage skipped.
```

Your standing prompt governs. Written by the Support Agent at the Owner's instruction on
**19/09 16:30**; every figure below was measured by command this afternoon — re-derive before you
record any of it.

## 0 · What the outage did — dates, not adjectives

| | |
|---|---|
| your last commit | `ed970da director: DEC-087 + DEC-088`, **16/09 08:02** |
| last Coder commits | P3-T03 report **08:09** (`38298d9`), P6-T05 report **08:22** (`8a0cbbb`) — both after your run |
| host reboot | **16/09 22:24:19** (`uptime -s`); the server was down until 19/09 |
| gate rows missing | **16/09, 17/09, 18/09** — the log ends at 15/09 20:11 (DEC-079). Write them as "no run — outage", dated, so the log does not read as if the days did not exist |
| working tree | clean; every prompt file the Support Agent wrote on 15/09 is committed |

## 1 · Reconcile the board with git — four reports are waiting, two rows are stale

| task | `STATE.md` says | git says | action |
|---|---|---|---|
| **P3-T03** | `todo`, `DISPATCHED: 2026-09-16` | branch `38298d9` "report + STATE.md row set to review"; 2 commits ahead of `main`; `P3-T03.report.md` on the branch | row → `review`; E1; dispatch Reviewer |
| **P3-T07** | `review` | 2 commits ahead; report on branch; no review file | E1; dispatch Reviewer |
| **P3-T08** | `review` | 3 commits ahead; report on branch; no review file | E1; dispatch Reviewer |
| **P6-T05** | `in-progress` | branch `8a0cbbb` "report + STATE.md row -> review"; 4 commits ahead | row → `review`; E1; dispatch Reviewer |

Shipping-state facts for E1 (DEC-046): merge-bases are `f5f1a44` (T03, T07) and `d2f4e4e`
(T08, T05); `main` is `ed970da`. **`main` gained no `backend/` file since `f5f1a44`** — measured:
`git diff f5f1a44..main --name-only | grep '^backend/'` is empty — so the composition risk this
time is between the four branches themselves, not with `main`. Their `backend/` files are
disjoint (`security/linter.py` · `security/detector.py` · `security/gate.py`+`output_guard.py` ·
`tests/test_lab_tag.py`+`eval/`), but three of them live in `security/` and will be merged in one
batch: **scratch-worktree the batch and run the suite there before `main`** (DEC-047).

The Reviewer scope notes are in `docs/plan/prompts/reviewer-run-2026-09-19.md`; the Owner opens
four sessions from it. **22 worktrees exist**, most for merged tasks — prune the merged ones
(`git worktree remove`) or the DEC-045 read-back becomes noise.

## 2 · Host — alive, and one thing changed under the reboot

| | measured 19/09 16:19 |
|---|---|
| manager | daemons up since 16/09 22:24:55; heartbeat **521** beats in the indexer, latest `09:16:43Z` and `09:06:42Z` — 600 s apart. Rule file and stanza **survived the reboot** (DEC-069's durability claim, now proved on the hard case) |
| indexer through the app's own `load()` | `wazuh-alerts-*` **7,352** documents; `soc_ro` reads, TLS verifies |
| **`alerts.json`** | mode **640** after the reboot — `user1` **can no longer read it** (`Permission denied`). Every file-based check in the record (`grep -c '"id":"100999"' /data/wazuh/logs/alerts/alerts.json`) now fails for the wrong reason. **Use the indexer count instead**; it is the source the application reads anyway |
| **worker + puller** | **NOT running** (`ps` shows no `app.web.worker` / `app.infra.puller`). `alerts` in `soc_dev` is unchanged since DEC-079: `replay` 92,011 + `wazuh` 3,941 = 95,952, while the indexer holds 7,352 — **≈ 3,400 live documents since 16/09 are not ingested**. The cursor in `source_cursor` makes this a catch-up, not a loss, but it is an Owner action **before the lab (22/09)** and worth starting now to prove the cursor survived the reboot |
| clamav | **installed** (4 packages) — P6 item (2)'s `apt install` is done; the agent-side `<localfile>` and the auditd `execve` check are **not measured** (need root) |

## 3 · The 20/09 trigger will not fire, and the schedule slipped anyway — put this on the Owner's table

`STATE.md:104` arms ② to fall "if P2's exit gate is not met by end of 20/09". **P2's gate is met
(DEC-079, 15/09).** The trigger's condition is satisfied, so it stays silent — while the situation
it was built to protect against has happened: **3.3 days lost**, DEC-071's two buffer days
(20–21/09) already consumed, P3 due 17/09 at 5/12 done, P4 due 18/09 at 0 cards, P5 due today at
0 cards. A trigger that watches the wrong gate is DEC-044's class in schedule form.

You cannot re-decide the cut (slip > 1 day is the Owner's, README:49). What you can do this run:

1. **Rewrite `STATE.md:104`** to say the condition is met and the trigger is inert, with the
   slip in numbers, and hand the Owner the two options with a recommendation — the Support Agent
   has already discussed both with the Owner; carry the same framing:
   - **A′ — cut ② now** (§10 first item; keep digest UI, health job, login, auto-close). P5 has
     zero cards, so nothing built is lost; it returns the one day the outage took.
   - **A″ — re-arm the trigger on the right condition**: *"if P6-T02 (the labelling page) is not
     merged and `eval/gold_candidates.csv` not built by end of 25/09, ② is cut"* — and even if it
     survives, ② gets exactly one day, **28/09**, with DEC-032's 60k-token measurement first.
2. **Keep `STATE.md:105`** (labeller names + dates for 26–27/09, due 20/09) — that one is
   unchanged and still binding. **Add** the advisor's `admin` account (P6 item (1)), which needs
   P4-T01's seed CLI — see §4.

## 4 · The critical path to 26–27/09 — corrected, and it runs through P4

`STATE.md:105` says "trang gán nhãn là sản phẩm của P4". Precisely: the blind labelling page is
**P6-T02**, and `P6-T02.prompt.md:17,28` makes it depend on **P6-T01** (candidate CSVs), **P2-T07**
✓, **P3-T06** ✓, and **P4's auth, visibility filter and base layout** — i.e. P4-T01, T02, T04, not
all of P4. So:

```
Planner P4 (not run)  ──►  P4-T01 auth ─┐
                            P4-T02 vis  ─┼──►  P6-T02 labelling page ──►  26–27/09 labelling
                            P4-T04 base ─┘          ▲
P6-T01 build_gold G1 (dispatchable now) ────────────┘
```

**Planner P4 must run today or tomorrow, in parallel with P3 — not after it.** The Owner has the
paste line (`planner-run-P4-2026-09-19.md`). **Before the Planner reads `prompts/P4.md`, sweep it
(DEC-031/DEC-054 treatment)** — it was last swept 14/09 23:52 and cites nothing after DEC-066.
Binding since then: **DEC-070** (indexer value), **DEC-071** (its date is 18/09, already past),
**DEC-079** (P2 closed — its "what P2/P3 built" list must be checked against `main`: `tier1/`,
`web/main.py`, `web/worker.py`, `security/`, `llm/`, `kb/` all exist), **DEC-082/083** (inventory
loaded; the replayed corpus in `soc_dev` is not G1 — the pilot's queue is that corpus), **DEC-085**
(`source='lab'` retag — the `labeling` mode's forbidden-substring test must still hide `source`),
**DEC-086** (G1 = 300 + |G2| — the admin labels route sizing), **DEC-088** (3-session cap, one slot
held by P6). If the Planner has already started when you read this, do the sweep as an E5 check
on its output instead.

P6 wave 1 per `P6-tasks.md:25`: T01 ‖ T04 ‖ T05 (≈ 5 h); wave 2: T02 ‖ T03 (≈ 4.5 h). **P6-T01
and P6-T04 are dispatchable now**; only the cap held them (DEC-088).

## 5 · Slot plan 20–25/09 — 18 slot-days, ≈ 11 needed, review cadence is the real limit

| day | slots (≤ 3) |
|---|---|
| 19/09 pm | Reviewers ×4 (T03, T07, T08, P6-T05) · Planner P4 · Director intake |
| 20/09 | merge the four → P3-T09 · **P4-T01** · **P6-T01** |
| 21/09 | P3-T10 · P4-T02 · P4-T04 |
| 22/09 | P3-T11 · **P6-T02** · P4-T03 — lab day 1 (Owner runs scenarios, worker+puller up) |
| 23/09 | P3-T12 · P4-T05 · P6-T03 — lab day 2 |
| 24/09 | P4-T06/T07/T08 · P6-T04 — lab day 3 |
| 25/09 | build_gold (Owner, item (4)) · buffer |

T09 heads P3's chain (T09 → T10 → T11 is the "① runs live on ≥ 50 replayed alerts" gate item),
so it takes a slot the moment T03 merges. Order P4 by what P6-T02 needs: **T01, T02, T04 first**;
T03/T05/T06 after; T07/T08 last. Every day without three sessions running pushes P6-T02 past
22/09 and the labelling weekend with it.

## 6 · Two stale rows to close, no decision needed

- `STATE.md:98` "commit hoặc bác `test_dispatch_state.py`" — **already committed**: `c522d9c`
  15/09 "invariant 3 skips off main, and `_on_main` sees detached worktrees" (the DEC-080
  hardened form); working tree clean. Tick it.
- `STATE.md:93` "trả lời INBOX 2026-09-15 · P3 / P4 / P6 · QUESTION" — the INBOX side is
  **resolved by DEC-082** (`INBOX.md:388`); the action row was never ticked. Tick it, or say what
  remains.

## 7 · Do not

- Do not decide the ② cut; frame A′/A″ and stop. Do not let the trigger stay written against
  P2's gate.
- Do not count on `alerts.json` for any check; do not run `sg wazuh` or anything under `/var/ossec`.
- Do not dispatch P6-T02 before P4-T01/T02/T04 and P6-T01 are in `main`; its card refuses to start
  otherwise (`:17`).
- Do not commit outside `docs/plan/`.

## 8 · Output

Result-intake block, then the evening-gate block with **three dated "outage" rows plus today's**.
Under **Gate**, P3's four items (`01-plan.md` P3 row) measured by command — the linter and gate
tests exist on branches, not on `main`, until the batch merges; say so. Every figure with its
denominator; every file claim with `file:line`. Commit `docs/plan/` by name —
`director: 2026-09-19 pm`.
