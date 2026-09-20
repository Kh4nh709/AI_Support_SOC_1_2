"""The routers `web/main.py` mounts, discovered from this package (P4-tasks.md
planning decision 1): every module here exposes `router: APIRouter`, and a
later card adds one module without touching any shared file.

No `try/except` around the attribute access on purpose. A module that forgets
`router` must be an `AttributeError` when the app starts — a router that
silently fails to mount is the DEC-039 shape, and fail-fast is the point.
"""

from __future__ import annotations

import importlib
import pkgutil

from fastapi import APIRouter


def iter_routers() -> list[APIRouter]:
    """Every module's `router`, in module-name order."""
    routers: list[APIRouter] = []
    for info in sorted(pkgutil.iter_modules(__path__), key=lambda i: i.name):
        module = importlib.import_module(f"{__name__}.{info.name}")
        routers.append(module.router)
    return routers
