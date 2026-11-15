"""DEC-221, card AP-T2: `rag.entries.title_of`, the one read-only helper this card adds under `backend/app/rag/`
(the Tier 1 analysis lists each RAG candidate with the title of its knowledge entry). Pure: no database; the
database read that uses it (`entry_cards`) is tested in `test_analysis_db.py`.

The title is the first `# ` heading of an entry's Markdown, which `render_entry_markdown` writes once, after the
front matter. The admin page (`web/routers/admin_knowledge.title_of`) reads it the same way; the test holds the two
copies equal, as the repository does for every number two pages share.
"""

from __future__ import annotations

import pytest
from app.rag import entries
from app.web.routers import admin_knowledge

_FIELDS = {
    "entry_id": "11111111-1111-1111-1111-111111111111",
    "version": 1,
    "title": "Quét cổng từ máy quản trị nội bộ",
    "conclusion": "closed_benign",
    "category": "scan",
    "summary": "Quét định kỳ của đội vận hành.",
}


def test_the_title_of_a_rendered_entry_is_its_heading():
    content = entries.render_entry_markdown(_FIELDS)
    assert entries.title_of(content) == "Quét cổng từ máy quản trị nội bộ"


def test_a_title_that_looks_like_a_heading_keeps_what_the_renderer_wrote():
    content = entries.render_entry_markdown({**_FIELDS, "title": "## not a section"})
    assert entries.title_of(content) == "## not a section"


@pytest.mark.parametrize(
    "content",
    [
        "",
        "no heading at all",
        "---\ntitle: x\n---\n\nbody only\n",
        "# first line, no newline before it\n",
        "text\n# heading without a closing newline",
    ],
)
def test_content_without_a_heading_gives_none(content):
    assert entries.title_of(content) is None
    assert admin_knowledge.title_of(content) is None


@pytest.mark.parametrize(
    "content",
    [
        entries.render_entry_markdown(_FIELDS),
        entries.render_entry_markdown({**_FIELDS, "title": "  spaced   out  "}),
        "---\nx: 1\n---\n# one\n\n# two\n",
        "\n# only after a blank line\nrest",
    ],
)
def test_it_reads_the_title_exactly_as_the_admin_page_does(content):
    assert entries.title_of(content) == admin_knowledge.title_of(content)


def test_what_is_not_text_gives_none():
    assert entries.title_of(None) is None  # type: ignore[arg-type]
    assert entries.title_of(7) is None  # type: ignore[arg-type]
