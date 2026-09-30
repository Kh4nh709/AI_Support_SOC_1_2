"""P10-T13 — the source guard over `tier2/investigation_view.py` and `tier2/case_view.py`: model
text and raw logs leave the views as plain values, never as markup.

The retired Jinja investigation page had its own guard (`test_pages_investigation.py`,
`test_the_template_and_router_never_mark_model_text_safe`), which read the page's router and
its `_investigation.html` — both deleted with the page. The view itself is the one module that
survives and that hands model output (summary, quotes, `stopped_by`) to the React case page
through `GET /api/tier2/cases/{id}/investigation`; if it ever wraps a string as safe markup,
`Markup(...)` / `mark_safe(...)` / `|safe` would let a hostile model string reach a renderer
that trusts it. The React page renders text only, but the guarantee is cheapest to hold at
the source: no `Markup`, no `|safe`, no `mark_safe`.

A pure source scan: no database, so it runs in `make test`.
"""

from __future__ import annotations

from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parents[1]
INVESTIGATION_VIEW = BACKEND / "app" / "tier2" / "investigation_view.py"
CASE_VIEW = BACKEND / "app" / "tier2" / "case_view.py"
GUARDED = [INVESTIGATION_VIEW, CASE_VIEW]
GUARDED_IDS = [path.stem for path in GUARDED]

#: What may never appear in the module: the constructor and the two spellings of the filter
#: (Jinja accepts both `|safe` and `| safe`), the helper Django-style code reaches for, and
#: the library they all come from.
FORBIDDEN = ("Markup", "|safe", "| safe", "mark_safe", "markupsafe")


def unsafe_markers(path: Path) -> list[str]:
    """The `FORBIDDEN` strings found in `path`'s text, in `FORBIDDEN`'s order."""
    source = path.read_text(encoding="utf-8")
    return [needle for needle in FORBIDDEN if needle in source]


@pytest.mark.parametrize("module", GUARDED, ids=GUARDED_IDS)
def test_the_views_never_mark_model_text_safe(module: Path) -> None:
    assert module.is_file()
    assert unsafe_markers(module) == []


@pytest.mark.parametrize("module", GUARDED, ids=GUARDED_IDS)
@pytest.mark.parametrize(
    ("injected", "expected"),
    [
        ("from markupsafe import Markup\n", ["Markup", "markupsafe"]),
        ("from jinja2 import Markup\n", ["Markup"]),
        ("x = Markup(summary)\n", ["Markup"]),
        ("from django.utils.safestring import mark_safe\n", ["mark_safe"]),
        ("TEMPLATE = '{{ summary|safe }}'\n", ["|safe"]),
        ("TEMPLATE = '{{ summary | safe }}'\n", ["| safe"]),
    ],
)
def test_the_guard_goes_red_on_a_scratch_copy(tmp_path, module, injected, expected) -> None:
    """The scan is live: each guarded module with one forbidden line added — on a scratch copy,
    never in the real file — is flagged, and only for the line that was added."""
    scratch = tmp_path / module.name
    scratch.write_text(injected + module.read_text(encoding="utf-8"), encoding="utf-8")

    assert unsafe_markers(scratch) == expected
    assert unsafe_markers(module) == []  # the real file is not the one touched
