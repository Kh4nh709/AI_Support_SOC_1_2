"""A task cannot reach `approved` or `done` without a committed Reviewer verdict.

WHY THIS EXISTS (DEC-028). P1-T02 and P1-T03 were both reviewed properly: the
Reviewers ran every acceptance command, wrote a full `.review.md`, and set their
STATE.md row to `approved`. Both then reported truthfully that they had done so.
Neither artifact reached anyone. They were written *inside the task worktree*,
left untracked, and the Director never looks in a sibling worktree. The verdicts
reached the merge only because they were also stated in chat; nothing in the
repository carried them.

Measured, because the first draft of this docstring overstated it: `git worktree
remove` REFUSES on untracked files (`fatal: … contains modified or untracked
files`, exit 128) and the file survives. Only `--force` destroys it, and that is
silent. So the refusal is a safety net nobody was reading — a Director cleaning
up and hitting that fatal is being told there is unrescued work in there.

The gap that allowed it: context pack §12 artifact-tests the Coder's report ("the
task report exists") but only outcome-tests the Reviewer's ("the Reviewer
returned APPROVE"), and `prompts/reviewer.md` says *write* the file and *update*
the row without ever saying *commit* them. In the main checkout that omission was
harmless. Under DEC-010's worktree-per-task isolation it is a loss channel.

WHERE THIS TRIPS. Not at the Reviewer — their row edit is invisible until it
lands. It trips at the Director's merge: marking a row `done` without a tracked
verdict file fails this test. That is the stage that matters, because `done` is
the claim that the definition of done in §12 was met.

TRACKED, NOT MERELY PRESENT. The check is `git ls-files`, not `path.exists()`.
The exact failure being guarded against was a file that existed on disk and in no
commit, so existence alone would have passed while the artifact was still one
`worktree remove --force` from gone.

ESCAPE. A row that is legitimately `done` with no review carries
`review-waived: <reason>` in any cell; say why, the way `superseded-ok` works.
"""

import pathlib
import re
import subprocess

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
STATE_PATH = REPO_ROOT / "docs" / "plan" / "STATE.md"
WAIVER_MARKER = "review-waived:"

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
# `approved` = Reviewer APPROVE awaiting merge; `done` = merged by the Director.
# Both assert a verdict was returned, so both owe the artifact that records it.
NEEDS_VERDICT = {"approved", "done"}

ROW_RE = re.compile(r"^\|\s*(P\d+-T\d+)\s*\|")


def _rows():
    """(task_id, status, raw_line) for every task row in STATE.md.

    Parsed by locating the one cell whose text is exactly a status token rather
    than by column position: the table's rows do not all carry the same number
    of cells, so positional indexing silently reads the wrong column.
    """
    out = []
    for line in STATE_PATH.read_text(encoding="utf-8").splitlines():
        m = ROW_RE.match(line)
        if not m:
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        hits = [c for c in cells if c in STATUSES]
        out.append((m.group(1), hits[0] if len(hits) == 1 else None, line))
    return out


def _tracked(rel: str) -> bool:
    """True when git has the path staged or committed (not merely on disk)."""
    proc = subprocess.run(
        ["git", "ls-files", "--error-unmatch", "--", rel],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.returncode == 0


_ROWS = _rows()


def test_state_table_is_parseable():
    """Guard the guard: if the table stops parsing, the checks below go vacuous."""
    assert _ROWS, f"no task rows matched in {STATE_PATH}"
    unreadable = [(tid, line[:90]) for tid, status, line in _ROWS if status is None]
    assert not unreadable, (
        "rows with no single unambiguous status cell — the parser would read these "
        f"as having no status and skip them: {unreadable}"
    )


def test_repo_is_a_git_checkout():
    """Guard the guard: without git, _tracked() is False for everything."""
    assert (REPO_ROOT / ".git").exists(), f"{REPO_ROOT} is not a git checkout"


@pytest.mark.parametrize(
    "task_id,status,line",
    [r for r in _ROWS if r[1] in NEEDS_VERDICT],
    ids=[f"{r[0]}-{r[1]}" for r in _ROWS if r[1] in NEEDS_VERDICT],
)
def test_approved_or_done_row_has_a_committed_verdict(task_id, status, line):
    if WAIVER_MARKER in line:
        pytest.skip(f"{task_id}: {WAIVER_MARKER} waiver on the row")
    phase = task_id.split("-")[0]
    rel = f"docs/plan/tasks/{phase}/{task_id}.review.md"
    path = REPO_ROOT / rel
    assert path.is_file(), (
        f"{task_id} is `{status}` in STATE.md but {rel} does not exist. "
        "A Reviewer verdict that lives only in chat is not an artifact (DEC-028). "
        f"If this row is legitimately verdict-free, put `{WAIVER_MARKER} <reason>` on it."
    )
    assert _tracked(rel), (
        f"{task_id} is `{status}` and {rel} exists but git does not track it. "
        "This is the exact P1-T02/P1-T03 failure: written in a worktree, never "
        "committed, so it reaches no merge and no reader. `git add` it (DEC-028)."
    )
