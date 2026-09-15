"""A task the board says was dispatched must have a branch to have been dispatched onto.

WHY THIS EXISTS (DEC-045). On 06/09 the Director printed "Dispatch now: P1-T05,
P1-T06, P1-T08" having created no worktree and no branch, and the Owner found the
slots idle. The rule "the Director creates the worktree at dispatch" was then
written into `coder-template.md`, `README.md` and `HUONG-DAN-VAN-HANH.md` — every
document except `prompts/director.md`, the one the Director reads every run. On
07/09 it recurred exactly: "three slots, all three filled", zero worktrees, and
the Owner created P2-T02's and P2-T04's by hand so dispatch was not held up.

A rule that lives only where it is not read is a vacuous guard in prose form.
So the rule now lives in `director.md`'s morning run and its E-triggers, and this
test is the mechanical half.

WHAT IS CHECKED, AND WHY IT IS BRANCHES AND NOT WORKTREES. A worktree is local:
it is not in the object database, it does not survive a clone, and asserting one
exists would fail for every reader who is not on this machine. A branch travels.
`git worktree add ../<dir> -b task/<ID> main` creates both, so the branch is the
part of "dispatched" that a test can honestly see — and it is exactly what was
missing on 07/09: `task/P2-T02` did not exist anywhere. The worktree half stays
procedural, in `director.md`, where the actor reads.

THREE INVARIANTS.
  1. A row whose Dispatch cell carries the `DISPATCHED:` marker has `task/<ID>`.
  2. A row whose status says work has begun (`in-progress`, `review`, `approved`,
     `changes`) has `task/<ID>` — a Coder cannot have reported from nowhere.
  3. A row in `approved` — the status that means "merge me next" — has a branch
     that is NOT already an ancestor of `main`. See below.
Invariant 2 needs no marker and so cannot be silenced by forgetting one; that is
deliberate, because forgetting the marker is the same class of mistake as
forgetting the worktree.

WHY INVARIANT 3 (07/09). `task/P2-T02` was merged at `1b63780` and its content
reverted out at `18e82d5`, so the branch is an ancestor of `main` while none of
its code is in `main` — measured: `backend/app/infra/db.py` has 2 defs on the
branch and 0 on `main`. Run in a detached worktree at `main`, the Director's own
merge command answers **"Already up to date."**, exits 0, changes nothing, and
`make test` stays at its pre-merge number because the code is simply absent.
Nothing goes red. Invariant 3 makes that state fail on the board instead.

WHAT INVARIANT 3 CANNOT SEE, stated so nobody trusts it further than it goes.
If the Coder commits the fix on top of the already-merged branch, the branch is
no longer an ancestor and this guard passes — but the merge still does not
restore the reverted files: for a file the new commit did not touch, `theirs`
equals the merge base and git keeps `ours`. Measured on a stand-in: after that
merge `db.py` still had 0 defs. The guard catches the silent case; the composed
case is what `reviewer.md`'s DEC-046 route (construct `merge(branch, main)` and
run acceptance there) is for.
"""

import pathlib
import re
import subprocess

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
STATE_PATH = REPO_ROOT / "docs" / "plan" / "STATE.md"
DISPATCH_MARKER = "DISPATCHED:"

STATUSES = {
    "todo",
    "in-progress",
    "review",
    "approved",
    "changes",
    "done",
    "blocked",
    "cut",
}
# Statuses that can only be reached by an agent having worked on a branch.
WORK_BEGUN = {"in-progress", "review", "approved", "changes"}

ROW_RE = re.compile(r"^\|\s*(P\d+-T\d+)\s*\|")


def _rows():
    out = []
    for line in STATE_PATH.read_text(encoding="utf-8").splitlines():
        m = ROW_RE.match(line)
        if not m:
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        hits = [c for c in cells if c in STATUSES]
        out.append((m.group(1), hits[0] if len(hits) == 1 else None, line))
    return out


def _branches() -> set[str]:
    proc = subprocess.run(
        ["git", "for-each-ref", "--format=%(refname:short)", "refs/heads/"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    return set(proc.stdout.split())


def _rev(ref: str) -> str:
    proc = subprocess.run(
        ["git", "rev-parse", ref],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.stdout.strip()


def _on_main() -> bool:
    """True on `main`, and also in a DETACHED worktree sitting at main's commit.

    The `--abbrev-ref HEAD` form alone returns the literal string "HEAD" when
    detached, which would skip invariant 3 in exactly the place it matters most:
    `prompts/reviewer.md:11` mandates `git worktree add --detach` for the
    shipping-state route (DEC-046/047), and the module docstring's own motivating
    sentence is "Run in a detached worktree at `main`". Measured 15/09 in such a
    worktree: `--abbrev-ref HEAD` -> "HEAD" while `rev-parse HEAD` == `rev-parse
    main`. Comparing commits covers both. (The STATE.md-vs-`git show main:` form
    was rejected: it goes silent whenever the board has uncommitted edits, which
    is precisely while the Director is editing it.)
    """
    proc = subprocess.run(
        ["git", "rev-parse", "--abbrev-ref", "HEAD"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.stdout.strip() == "main":
        return True
    head, main = _rev("HEAD"), _rev("main")
    return bool(head) and head == main


_ROWS = _rows()
_BRANCHES = _branches()
_ON_MAIN = _on_main()


def test_git_is_readable():
    """Guard the guard: with no branches readable every assertion below is vacuous."""
    assert _BRANCHES, "git returned no branches — the checks below would pass on nothing"


def _is_ancestor_of_main(branch: str) -> bool:
    return (
        subprocess.run(
            ["git", "merge-base", "--is-ancestor", branch, "main"],
            cwd=REPO_ROOT,
            capture_output=True,
            check=False,
        ).returncode
        == 0
    )


@pytest.mark.parametrize(
    "task_id,status,line",
    [r for r in _ROWS if DISPATCH_MARKER in r[2] or r[1] in WORK_BEGUN],
    ids=[r[0] for r in _ROWS if DISPATCH_MARKER in r[2] or r[1] in WORK_BEGUN] or None,
)
def test_dispatched_task_has_a_branch(task_id, status, line):
    why = f"marked `{DISPATCH_MARKER}`" if DISPATCH_MARKER in line else f"status `{status}`"
    assert f"task/{task_id}" in _BRANCHES, (
        f"{task_id} is {why} in STATE.md but branch `task/{task_id}` does not exist. "
        "Dispatch is `git worktree add ../AI_Support_SOC_1_2-"
        f"{task_id} -b task/{task_id} main`, run by the Director *before* the task is "
        "announced (DEC-045) — announcing it is not dispatching it."
    )


@pytest.mark.skipif(
    not _ON_MAIN,
    reason="invariant 3 only (DEC-073): it compares this checkout's STATE.md snapshot "
    "against live git, but on a task branch `main` is the real ref while STATE.md is a "
    "snapshot — so after any merge to `main` every open branch goes red through no fault "
    "of its own. Invariants 1 and 2 are branch-safe and keep running everywhere.",
)
@pytest.mark.parametrize(
    "task_id",
    [r[0] for r in _ROWS if r[1] == "approved" and f"task/{r[0]}" in _BRANCHES],
    ids=[r[0] for r in _ROWS if r[1] == "approved" and f"task/{r[0]}" in _BRANCHES] or None,
)
def test_approved_task_has_something_left_to_merge(task_id):
    """`approved` means "merge me next"; a merge that changes nothing is a defect."""
    assert not _is_ancestor_of_main(f"task/{task_id}"), (
        f"{task_id} is `approved` in STATE.md but `task/{task_id}` is already an "
        "ancestor of `main`, so `git merge` will answer 'Already up to date.', exit 0 "
        "and land nothing. This is what a merged-then-reverted branch looks like "
        "(P2-T02, 18e82d5). Do not re-merge it: either revert the revert first, or "
        "have the Coder recreate the branch from current `main`. See the module "
        "docstring for what this guard cannot see."
    )
