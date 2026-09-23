"""web/templating.py — the Jinja2 environment every page card renders through
(P4-T04).

Autoescape is FastAPI's default for `.html`/`.xml` templates (`select_autoescape`)
already — set explicitly below anyway so the property is stated in this file,
not merely inherited from a library default (P4-T04's design note 1).
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from fastapi import Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
templates.env.autoescape = True

# An exact pinned version — never the floating alias this acceptance forbids.
HTMX_SRC = "https://cdnjs.cloudflare.com/ajax/libs/htmx/2.0.4/htmx.min.js"
# Verified 20/09 against the served file itself (`openssl dgst -sha512` on the
# downloaded `htmx.min.js` matches cdnjs's own published SRI for this version).
HTMX_INTEGRITY: str | None = (
    "sha512-2kIcAizYXhIn8TzUvqzEDZNuDZ+aW7yE/+f1HJHXFjQcGNfv1kqzJSTBRBSlOgp6B/KZsz1K0a3ZTqP9dnxioQ=="
)

_BAND_CLASS = {
    "Thấp": "band-low",
    "Vừa": "band-mid",
    "Cao": "band-high",
    "Rất cao": "band-crit",
}


def local_time(value: datetime | None, tz_name: str) -> str:
    """`value` rendered in `tz_name` as `dd/mm HH:MM:SS`; `""` for `None`.

    `tz_name` is passed explicitly by the caller (from `Cfg.DISPLAY_TZ` via the
    request's `get_config` dependency) rather than read at import time, because
    `config.load()` is not cached and must never run at module import in a test
    process (DEC-047).
    """
    if value is None:
        return ""
    return value.astimezone(ZoneInfo(tz_name)).strftime("%d/%m %H:%M:%S")


def band_class(value: str | None) -> str:
    """P4-T05's row class for a risk band; `""` for `None` or anything unknown."""
    return _BAND_CLASS.get(value, "")


templates.env.filters["local_time"] = local_time
templates.env.filters["band_class"] = band_class


def render(request: Request, name: str, **ctx: object) -> HTMLResponse:
    """Every page's context: `request`, `user` (`None` unless `ctx` overrides
    it), `flash` (from `ctx`), and the pinned `htmx_src`/`htmx_integrity`."""
    context: dict[str, object] = {
        "user": None,
        "flash": None,
        "htmx_src": HTMX_SRC,
        "htmx_integrity": HTMX_INTEGRITY,
    }
    context.update(ctx)
    return templates.TemplateResponse(request, name, context)
