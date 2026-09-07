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

TWO INVARIANTS.
  1. A row whose Dispatch cell carries the `DISPATCHED:` marker has `task/<ID>`.
  2. A row whose status says work has begun (`in-progress`, `review`, `approved`,
     `changes`) has `task/<ID>` — a Coder cannot have reported from nowhere.
Invariant 2 needs no marker and so cannot be silenced by forgetting one; that is
deliberate, because forgetting the marker is the same class of mistake as
forgetting the worktree.
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


_ROWS = _rows()
_BRANCHES = _branches()


def test_git_is_readable():
    """Guard the guard: with no branches readable every assertion below is vacuous."""
    assert _BRANCHES, "git returned no branches — the checks below would pass on nothing"


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
