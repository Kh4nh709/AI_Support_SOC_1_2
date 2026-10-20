"""P11-T19 (spec §8, DEC-205) — a source scan that pins what the removal left out: no template, no
templating module, no session cookie, no response that is a page or a redirect, anywhere in
`backend/app`.

The route-list test (`test_no_html_routes.py`) proves the app answers no page. This one proves the
parts behind it stay gone, so that a page cannot come back through an import that no route calls
yet: the Jinja environment (`web/templating.py`), the `templates/` directory, the cookie helpers in
`web/deps.py`, the name `soc_session`.

`backend/app/llm/templates/` is the LLM prompt-template directory (`triage_system.txt`,
`output_schemas.json`): it has nothing to do with pages, and the word `templates` is read there as
a path all over `app/llm`. So `templates` is looked for under `backend/app/web/` only, where it
named the Jinja directory; every other term is looked for in all of `backend/app`.

A source scan, as `test_import_rules.py` and `test_credential_hygiene.py` are: no database, runs in
`make test` and `make test-db`.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

APP = Path(__file__).resolve().parents[1] / "app"
WEB = APP / "web"

#: One entry per thing the retirement removed. Each is a word the code would need to bring a page,
#: or the cookie, back. Case-sensitive on purpose: `Jinja2Templates` and `TemplateResponse` are
#: class and method names; `jinja2` is the import; `soc_session` is the cookie's name.
APP_WIDE_TERMS = {
    "the Jinja environment module": r"\btemplating\b",
    "the session cookie's name": r"soc_session",
    "the cookie setter": r"set_session_cookie",
    "the cookie clearer": r"clear_session_cookie",
    "any cookie written": r"\b(set_cookie|delete_cookie)\b",
    "any cookie read": r"\.cookies\b",
    "the jinja2 package": r"\bjinja2\b",
    "Starlette's template class": r"Jinja2Templates",
    "a rendered template": r"TemplateResponse",
    "an HTML response": r"HTMLResponse",
    "a redirect response": r"RedirectResponse",
    "static files": r"StaticFiles",
}


def _python_files(root: Path) -> list[Path]:
    return sorted(path for path in root.rglob("*.py") if "__pycache__" not in path.parts)


def _hits(files: list[Path], pattern: str) -> list[str]:
    regex = re.compile(pattern)
    found = []
    for path in files:
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if regex.search(line):
                found.append(f"{path.relative_to(APP.parent)}:{number}: {line.strip()[:100]}")
    return found


def test_the_scan_reads_the_application() -> None:
    """Not vacuous: it finds the app's files, among them the ones whose neighbours were removed."""
    files = _python_files(APP)
    assert len(files) > 50
    assert WEB / "deps.py" in files and WEB / "main.py" in files


@pytest.mark.parametrize("what", sorted(APP_WIDE_TERMS))
def test_backend_app_does_not_contain(what: str) -> None:
    assert _hits(_python_files(APP), APP_WIDE_TERMS[what]) == []


def test_web_does_not_mention_templates() -> None:
    """The Jinja directory was `web/templates/`; under `web/` nothing names a template any more."""
    assert _hits(_python_files(WEB), r"\btemplates?\b") == []


def test_the_removed_files_are_gone() -> None:
    assert not (WEB / "templates").exists()
    assert not (WEB / "templating.py").exists()
    assert not (WEB / "routers" / "pages.py").exists()


def test_the_app_carries_no_html_file() -> None:
    """A page is a template or a static file: the app ships neither (the LLM prompt templates are
    `.txt` and `.json`)."""
    html = sorted(
        str(path.relative_to(APP.parent))
        for path in APP.rglob("*")
        if path.suffix in {".html", ".htm", ".j2", ".jinja", ".jinja2"}
    )
    assert html == []
