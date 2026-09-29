"""The worker's job-type -> handler table, discovered from this package
(P5-tasks.md planning decision 1 — mirrors `web/routers/__init__.py`'s
P4-tasks.md planning decision 1 for routers): every module here exposes
`JOB_TYPE: str` and `handle`, and a later card (`investigate`, `digest`,
`health`) adds one module without touching any shared file.

No `try/except` around the attribute access on purpose, and no `getattr`
default for `JOB_TYPE`/`handle`: a module that forgets either is an
`AttributeError` at import time — a handler that silently fails to mount is
the DEC-039 shape, and fail-fast is the point (the `routers/__init__.py`
docstring says this about routers; this says it about handlers).
`STATEMENT_TIMEOUT: str` is optional and only appears in `iter_timeouts()`'s
result when a module declares it.

A `JOB_TYPE` that is not in `app.infra.jobs.JOB_TYPES` is a `PermanentError`
naming the module and the value — the same guard `enqueue()` applies at
insert time (`infra/jobs.py:68`), here at import time instead. A duplicate
`JOB_TYPE` across two modules is a `PermanentError` too, not a silent
last-wins: two cards each claiming the same job type must fail loudly at
start-up, which is the whole reason this package exists.
"""

from __future__ import annotations

import importlib
import pkgutil
import re
from types import ModuleType

from app.infra.errors import PermanentError
from app.infra.jobs import JOB_TYPES
from app.infra.worker import Handler

#: The Postgres duration form this codebase's `STATEMENT_TIMEOUT` values actually take
#: (`"5s"`, `"250ms"`, `"3min"`) — the same three units `SET LOCAL statement_timeout`
#: accepts unambiguously without a space (P5-T01 review round 1, finding 4, deferred to
#: whichever module first declares a `STATEMENT_TIMEOUT`; P5-T04 is that module).
_STATEMENT_TIMEOUT_RE = re.compile(r"^\d+(ms|s|min)$")


def _load_modules() -> list[ModuleType]:
    """Every module directly under this package, imported, in module-name order."""
    modules: list[ModuleType] = []
    for info in sorted(pkgutil.iter_modules(__path__), key=lambda i: i.name):
        modules.append(importlib.import_module(f"{__name__}.{info.name}"))
    return modules


def iter_handlers() -> dict[str, Handler]:
    """Every module's `JOB_TYPE: handle`, keyed by `JOB_TYPE`."""
    handlers: dict[str, Handler] = {}
    for module in _load_modules():
        job_type = module.JOB_TYPE
        handle = module.handle
        if job_type not in JOB_TYPES:
            raise PermanentError(
                f"{module.__name__}: JOB_TYPE must be one of "
                f"{'|'.join(sorted(JOB_TYPES))}, got {job_type!r}"
            )
        if job_type in handlers:
            raise PermanentError(
                f"{module.__name__}: JOB_TYPE {job_type!r} is already claimed by another "
                "handler module"
            )
        handlers[job_type] = handle
    return handlers


def iter_timeouts() -> dict[str, str]:
    """Every module's `STATEMENT_TIMEOUT`, keyed by `JOB_TYPE`, for the modules
    that declare one — empty until the first one does.

    Validated against `_STATEMENT_TIMEOUT_RE` here, at discovery time, so a malformed
    value (a typo, a bare number with no unit, a space before the unit) is a
    `PermanentError` naming the module and the value — the same fail-fast shape
    `iter_handlers()` already gives a bad `JOB_TYPE` — rather than a `SET LOCAL
    statement_timeout = '...'` syntax error surfacing later, deep inside
    `infra/db.py::transaction()`, the first time the job actually runs.
    """
    timeouts: dict[str, str] = {}
    for module in _load_modules():
        statement_timeout = getattr(module, "STATEMENT_TIMEOUT", None)
        if statement_timeout is not None:
            if not _STATEMENT_TIMEOUT_RE.fullmatch(statement_timeout):
                raise PermanentError(
                    f"{module.__name__}: STATEMENT_TIMEOUT must match "
                    f"{_STATEMENT_TIMEOUT_RE.pattern!r} (Postgres duration form, e.g. "
                    f"'5s'), got {statement_timeout!r}"
                )
            timeouts[module.JOB_TYPE] = statement_timeout
    return timeouts
