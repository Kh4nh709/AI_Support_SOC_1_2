# How to run the 14-day build with agents

You (the Owner) coordinate four agent roles. Everything they need is in this folder. Nothing here requires a specific agent product; any agent that can read the repo, run commands and edit files works.

## Folder map

```
docs/plan/
  00-context-pack.md      shared context; every prompt points here  (read once yourself)
  01-plan.md              9 phases with deliverables and exit gates
  README.md               this file
  STATE.md                the board: phases, tasks, status, blockers   (agents update it)
  INBOX.md                decision requests and blockers for the Director
  DECISIONS.md            decisions taken (ADR-lite), by Director or by you
  prompts/
    P0.md … P8.md         Planner prompt per phase → produces task cards + coder prompts
    coder-template.md     template the Planner instantiates per task
    reviewer.md           standing prompt for the Reviewer
    director.md           standing prompt for the Director
  tasks/
    P<n>/                 created by the Planner: P<n>-tasks.md, <TASK_ID>.prompt.md, <TASK_ID>.report.md, <TASK_ID>.review.md
```

## The four roles

| Role | When you run it | Input you give | Output you get |
|---|---|---|---|
| **Planner** | Once per phase, at the start of the phase (and again if the Director asks for a re-plan) | `prompts/P<n>.md` | `tasks/P<n>/P<n>-tasks.md` (task cards) and one `tasks/P<n>/<TASK_ID>.prompt.md` per task, ready to paste |
| **Coder** | Once per task; up to 3 in parallel on disjoint files | `tasks/P<n>/<TASK_ID>.prompt.md` | Code on branch `task/<TASK_ID>`, tests, `tasks/P<n>/<TASK_ID>.report.md` |
| **Reviewer** | After each Coder finishes | `prompts/reviewer.md` + the task id | `tasks/P<n>/<TASK_ID>.review.md` with APPROVE or CHANGES |
| **Director** | Start of day, end of day, and whenever `INBOX.md` has a new item | `prompts/director.md` (it reads STATE/INBOX itself) | Updated `STATE.md`, entries in `DECISIONS.md`, a short list of things only you can do |

## The daily loop

1. **Morning (10 min).** Run the Director. It reads `STATE.md` and `INBOX.md`, resolves what it can, and prints "Owner actions" (things only you can do: credentials, lab runs, labeling, approvals). Do those first.
2. **If a new phase starts.** Run the Planner with `prompts/P<n>.md`. Read the task list once; if a task looks wrong, say so to the Director (it will re-plan), not to the Coder.
3. **Dispatch (DEC-010).** For each task in status `todo` whose dependencies are `done`: the Director creates its worktree in the morning run — `git worktree add ../AI_Support_SOC_1_2-<TASK_ID> -b task/<TASK_ID> main` — and you open one Coder session **inside that directory** with its `.prompt.md`. Max 3 at once, disjoint files. No agent ever shares a checkout; after merge the Director removes the worktree with a plain `git worktree remove` — a refusal means uncommitted work is stranded there (DEC-028).
4. **Review.** When a Coder reports, run the Reviewer with the task id. `CHANGES` → send the review file back to the same Coder. `APPROVE` → the Director merges (or you merge with `git merge --no-ff task/<TASK_ID>`) and marks `done`.
5. **Evening (10 min).** Run the Director for the daily gate: it checks the phase exit gate, applies the cut order if needed, and writes tomorrow's Owner actions.

Rule of thumb: if you find yourself explaining context to an agent in chat, the context pack is missing something — add it there, not in chat.

## What you do that agents cannot (see context pack §11)

Day 0: indexer read-only user, DeepSeek key, `conf/inventory.yaml` + `conf/identities.yaml`, check whether `Final-Project` code is reusable. Day 1: read the smoke-test report, approve the model. Day 2: heartbeat wodle + rule on the Wazuh manager. Day 3–4: write decision tables with the advisor. Day 5 onward: use the queue daily (pilot). Day 7: run lab scenarios. Day 8–9: label, adjudicate. Every day: 5-minute digest review. Any time: approve or refuse Decision Requests that the Director escalates.

## Escalation rules (short)

The Director decides alone: task order, minor design inside the frozen contracts, library choices, marking tasks done, applying the cut order **within** a phase's cut candidates. The Director must ask you: any change to a frozen contract (schema, output schemas, config keys, API list, import rules), any cut of a D-item, model change, schedule slip > 1 day, anything touching evaluation validity.

## Conventions you should know

- Task ids: `P<n>-T<nn>` (e.g. `P2-T07`). Branch: `task/P2-T07`.
- Status values in `STATE.md`: `todo`, `in-progress`, `review` (Coder reported), `approved` (Reviewer APPROVE, awaiting merge), `changes` (Reviewer CHANGES), `done` (merged by Director), `blocked`, `cut`.
- A task is never `done` without a Reviewer APPROVE and the acceptance commands passing in a clean checkout.
- Agents write English; the thesis stays Vietnamese. Existing Vietnamese identifiers are not renamed.

## If things go wrong

- Model fails the smoke test → Director opens a Decision Request with the numbers; you pick the fallback (another DeepSeek chat model through the same adapter).
- A phase is a day late → the Director proposes cuts from that phase's "cut candidates"; you approve. Never cut intake/puller, ① + gate + verifier, the labeling page, or the eval harness.
- Two Coders touched the same file → the Reviewer flags it; the Director re-assigns files; you merge in dependency order.
- An agent wants to change the schema → it must write to `INBOX.md`; you will see it in the Director's morning report.
