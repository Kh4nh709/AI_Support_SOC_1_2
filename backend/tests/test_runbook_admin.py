"""P11-T19 (DEC-205) — `docs/runbook.md`: the console's address, and the Owner's TWO steps as one
procedure, in order.

One story, not two. The deploy block (`## Admin console v1.1 — deploy (DEC-205)`, held row by row
by `test_runbook_deploy.py`) is the first Owner step; the retire step of this branch is the
second, in the same block, after the gate. This file pins the whole order across both:
fast-forward `main` to `director/admin-v1-1`, `make migrate`, the check that 19 migrations are in,
`docker compose up -d --build ui`, `docker compose restart app worker`; the Owner uses the React
pages; then fast-forward `main` to `director/admin-v1-1-retire` and `docker compose restart app
worker`: a code-only change, no migration and no UI rebuild. A runbook that swaps two of those
would be followed to the letter by the one person who runs it.

It also pins that the steps are written once (the `## Admin console` section points to the block
and repeats none), and that no liveness check of the stack uses a page port 8000 no longer has.

No database; reads the one file.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import pytest

RUNBOOK = Path(__file__).resolve().parents[2] / "docs" / "runbook.md"
BLOCK = "## Admin console v1.1 — deploy (DEC-205)"
CONSOLE = "## Admin console"


def _text() -> str:
    return RUNBOOK.read_text(encoding="utf-8")


def _section(heading: str) -> str:
    """The body after the `heading` line, up to the next `## ` heading; the heading is there once."""
    text = _text()
    starts = [m.end() for m in re.finditer(rf"^{re.escape(heading)}$", text, re.MULTILINE)]
    assert len(starts) == 1, f"expected one {heading!r} heading, found {len(starts)}"
    following = re.search(r"^## ", text[starts[0] :], re.MULTILINE)
    return text[starts[0] :] if following is None else text[starts[0] :][: following.start()]


def _retire_row() -> str:
    rows = [ln for ln in _section(BLOCK).splitlines() if ln.startswith("| **retire step**")]
    assert len(rows) == 1, f"expected one retire-step row in the deploy block, found {len(rows)}"
    return rows[0]


def test_the_admin_console_is_on_port_8080_under_admin() -> None:
    section = _section(CONSOLE)
    assert "`http://<host>:8080/admin`" in section
    # and the section says what port 8000 serves now
    assert "`/api/*`, `POST /webhook/alerts` and `GET /health`" in section
    assert "renders no page" in section


def test_the_console_section_lists_the_pages_that_stay_and_says_two_went() -> None:
    """P15-T01 (DEC-214): the rules page and the digest page left the UI; the section counts and names the rest."""
    section = _section(CONSOLE)
    found = re.search(r"has (\w+) pages: (.*?)\. Each calls", section, re.DOTALL)
    assert found, "the console section no longer says how many pages the admin has"
    count, pages = found.groups()
    assert count == "seven"
    # On the trial branch the lab labelling page of DEC-213 (P14-T10) stays, straight after the gold-set labelling.
    assert re.findall(r"`/admin/([a-z]+)`", pages) == [
        "overview",
        "users",
        "llm",
        "labels",
        "lab",
        "knowledge",
        "audit",
    ]
    assert "DEC-214" in pages


def test_no_sentence_sends_the_operator_to_a_page_the_ui_no_longer_has() -> None:
    """P15-T01 (DEC-214): `/admin/rules` and `/admin/digest` are named only in the sentences about the Jinja pages
    that port 8000 stopped serving (P11-T19); no row, no alarm and no step sends anyone to them. The API routes
    (`/api/admin/rules`, `/api/admin/digest`) are not pages and stay nameable."""
    for number, line in enumerate(_text().splitlines(), start=1):
        for page in ("/admin/rules", "/admin/digest"):
            if re.search(rf"(?<!/api){re.escape(page)}", line):
                assert (
                    "8000" in line
                ), f"line {number} sends the operator to {page}, a page the UI no longer has"


def test_the_two_owner_steps_are_one_procedure_in_dec_205s_order() -> None:
    block = _section(BLOCK)
    in_order = [
        "git merge --ff-only director/admin-v1-1` (on `main`)",  # the v1.1 deploy, rows 1 to 5
        "make migrate PY=.venv/bin/python",
        'select count(*) from schema_migrations"',
        "docker compose up -d --build ui",
        "docker compose restart app worker",  # row 5
        "the gate of spec §8",  # the Owner uses the React pages
        "git merge --ff-only director/admin-v1-1-retire",  # the retire step
    ]
    positions = [block.index(step) for step in in_order]
    assert positions == sorted(positions), dict(zip(in_order, positions))
    # the retire step's own restart comes after its fast-forward, in its own row
    row = _retire_row()
    assert row.index("director/admin-v1-1-retire") < row.index(
        "`docker compose restart app worker`"
    )
    assert positions[-1] == block.index(row) + row.index("git merge --ff-only")


def test_the_retire_step_is_a_fast_forward_and_a_restart_and_nothing_else() -> None:
    row = _retire_row()
    command = row.split("|")[2]
    assert "`git merge --ff-only director/admin-v1-1-retire` (on `main`)" in command
    for forbidden in ("make migrate", "--build", "docker compose up"):
        assert forbidden not in command, forbidden
    assert "no migration and no `ui` rebuild" in row


def test_the_retire_step_waits_for_the_deploy_and_the_migration_count() -> None:
    block = _section(BLOCK)
    paragraph = next(p for p in block.split("\n\n") if p.startswith("**The retire step"))
    assert "only after the deploy above" in paragraph
    assert "reads `19`" in paragraph  # stacked on v1.1: it carries all of v1.1's code


def test_the_steps_are_written_once() -> None:
    """The `## Admin console` section points to the block and carries no copy of the commands, and
    each command of the release is in the block only (not in the `UI` or the `Admin console`
    sections, which may name a branch but never give the command)."""
    text = _text()
    assert "git merge --ff-only director/admin-v1-1`" in _section(BLOCK)
    # the v1.1 deploy's command ends at its branch name (a backtick), so the retire command, which
    # begins the same way, is not counted as a second copy of it
    assert len(re.findall(r"git merge --ff-only director/admin-v1-1`", text)) == 1
    assert len(re.findall(r"git merge --ff-only director/admin-v1-1-retire`", text)) == 1
    console = _section(CONSOLE)
    for command in ("make migrate", "docker compose up -d --build ui", "docker compose restart"):
        assert command not in console, f"the Admin console section repeats {command!r}"
    assert BLOCK.removeprefix("## ") in console  # and it says where the steps are


MERGE = "0c6d7b9"  # the merge commit of the retire branch (parents: P11-T19's side, the v1.1 tip)
WHERE_ROW = "the UI section's rollback row"
WHERE_PARAGRAPH = "the retire step's rollback paragraph"


def _rollback_texts() -> dict[str, str]:
    """The two places the rollback of the retire step is written: the row of the `UI (service
    `ui`)` table and the paragraph after the retire step's own row."""
    text = _text()
    row = [ln for ln in text.splitlines() if ln.startswith("| **rollback** of P11-T19")]
    assert len(row) == 1, f"expected one rollback row in the UI section, found {len(row)}"
    paragraphs = _section(BLOCK).split("\n\n")
    paragraph = [p for p in paragraphs if p.startswith("**Rollback of the retire")]
    assert len(paragraph) == 1, "the retire step's rollback paragraph is gone"
    return {WHERE_ROW: row[0], WHERE_PARAGRAPH: paragraph[0]}


@pytest.mark.parametrize("where", [WHERE_ROW, WHERE_PARAGRAPH])
def test_the_rollback_reverts_the_merge_commit_on_its_second_parent(where: str) -> None:
    """The newest `P11-T19:` commit is a MERGE (`0c6d7b9`; parents: the retire branch's own side and
    the v1.1 tip `17ae66c`). `git revert` refuses a merge without `-m`; `-m 1` would take out all of
    v1.1 and keep the retire changes; reverting the older commits one by one conflicts. The mainline
    is the v1.1 tip: `-m 2`. Commits after the merge (fix commits) are reverted first."""
    text = _rollback_texts()[where]
    assert f"`git revert --no-edit -m 2 {MERGE}`" in text
    assert f"`git log --format=%h {MERGE}..`" in text  # how to list what came after it
    assert f"every commit after `{MERGE}`, newest first" in text
    assert "`docker compose restart app worker`" in text
    order = [
        f"every commit after `{MERGE}`, newest first",
        f"git revert --no-edit -m 2 {MERGE}",
        "docker compose restart app worker",
    ]
    positions = [text.index(step) for step in order]
    assert positions == sorted(positions), dict(zip(order, positions))
    # the wording that could not be followed is gone
    assert "each `P11-T19:` commit" not in text
    assert "`git revert` each" not in text
    assert "-m 1" not in text


def test_the_old_rollback_wording_is_gone_from_the_whole_runbook() -> None:
    assert "each `P11-T19:` commit" not in _text()
    assert "a fast-forwarded merge has no merge commit" not in _text()


GIT_ENV = {
    "GIT_AUTHOR_NAME": "t",
    "GIT_AUTHOR_EMAIL": "t@example.invalid",
    "GIT_COMMITTER_NAME": "t",
    "GIT_COMMITTER_EMAIL": "t@example.invalid",
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_CONFIG_SYSTEM": "/dev/null",
}


def _git(repo: Path, *args: str, check: bool = True) -> str:
    env = {**GIT_ENV, "PATH": os.environ["PATH"]}
    done = subprocess.run(
        ["git", *args], cwd=repo, env=env, capture_output=True, text=True, check=False
    )
    if check:
        assert done.returncode == 0, f"git {' '.join(args)}: {done.stderr.strip()}"
    return done.stdout.strip()


def test_the_documented_revert_sequence_gives_back_the_v1_1_tree(tmp_path: Path) -> None:
    """The shape of the real history, in a scratch repository (never this one): a base, a v1.1 tip
    that changes a file the retire side changed too, a retire branch that deletes what the retire
    step deletes, the merge of the v1.1 tip into it (parents: the retire side, then the v1.1 tip,
    one conflict resolved by hand), and a fix commit after it. `main` is fast-forwarded to the
    retire branch. The runbook's sequence (the commits after the merge, newest first, then the merge
    with `-m 2`) leaves a tree equal to the v1.1 tip's, for every path."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    (repo / "pages.py").write_text("page\n")
    (repo / "api.py").write_text("api\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "base")
    _git(repo, "checkout", "-q", "-b", "retire")
    (repo / "pages.py").unlink()  # P11-T19: the page goes
    (repo / "api.py").write_text("api, cookie gone\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "P11-T19: removal")
    _git(repo, "checkout", "-q", "-b", "v11", "main")
    (repo / "api.py").write_text("api\nv1.1 route\n")
    (repo / "new_page.tsx").write_text("react\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "v1.1")
    v11_tip = _git(repo, "rev-parse", "HEAD")
    _git(repo, "checkout", "-q", "retire")
    retire_side = _git(repo, "rev-parse", "HEAD")
    _git(repo, "merge", "--no-edit", "v11", check=False)  # conflicts in api.py: both sides survive
    (repo / "api.py").write_text("api, cookie gone\nv1.1 route\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "--no-edit")
    merge = _git(repo, "rev-parse", "HEAD")
    assert _git(repo, "rev-list", "--parents", "-n", "1", merge).split()[1:] == [
        retire_side,
        v11_tip,
    ], "the merge's second parent is the v1.1 tip"
    (repo / "NOTES.md").write_text("a fix after the merge\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "P11-T19: fix round")
    _git(repo, "checkout", "-q", "main")
    _git(repo, "merge", "-q", "--ff-only", "retire")

    # a plain revert of the merge is refused (why the runbook gives -m)
    refused = subprocess.run(
        ["git", "revert", "--no-edit", merge],
        cwd=repo,
        env={**GIT_ENV, "PATH": os.environ["PATH"]},
        capture_output=True,
        text=True,
        check=False,
    )
    assert refused.returncode != 0 and "no -m option was given" in refused.stderr

    # the runbook's rollback, on `main`
    after = _git(repo, "log", "--format=%h", f"{merge}..").split()
    assert len(after) == 1
    for sha in after:  # newest first, as `git log` lists them
        _git(repo, "revert", "--no-edit", sha)
    _git(repo, "revert", "--no-edit", "-m", "2", merge)

    assert _git(repo, "diff", "--stat", v11_tip) == ""
    assert _git(repo, "rev-parse", "HEAD^{tree}") == _git(repo, "rev-parse", f"{v11_tip}^{{tree}}")


@pytest.mark.parametrize(
    "first_cells", ["**up?** `app` |", "h |"], ids=["start-and-stop up? app", "pilot row h"]
)
def test_no_liveness_check_of_the_app_uses_the_page_port_8000_no_longer_has(
    first_cells: str,
) -> None:
    lines = [ln for ln in _text().splitlines() if ln.startswith(f"| {first_cells}")]
    assert len(lines) == 1, (first_cells, len(lines))
    line = lines[0]
    assert "127.0.0.1:8000/api/auth/me" in line
    assert "127.0.0.1:8000/login" not in line


def test_no_curl_asks_port_8000_for_a_page_except_to_expect_the_404() -> None:
    """A `curl` of `:8000/login` or `:8000/admin…` in the runbook is only ever the check that the
    page is GONE (the retire step's `404`), never a way to see the stack is up."""
    bad = []
    for number, line in enumerate(_text().splitlines(), start=1):
        for match in re.finditer(r"curl[^`|]*?:8000/(login|logout|admin)[^`|]*", line):
            if "`404`" not in line:
                bad.append((number, match.group(0)))
    assert bad == []
