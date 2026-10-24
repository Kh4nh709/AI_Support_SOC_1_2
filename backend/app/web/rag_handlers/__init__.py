"""The `rag-worker`'s job-type -> handler table, discovered from this package (P13-T03, DEC-210).

The contract is `app.web.handlers`'s own, over a package of its own: every module here exposes
`JOB_TYPE: str` and `handle`, and optionally `STATEMENT_TIMEOUT: str`. Spec §7.1: the RAG handlers are
**not** under `web/handlers/`, which the main worker mounts entirely — `rag-worker` claims `rag_lookup`
and `knowledge_draft`, and the main worker claims neither, so a later card adds a module here and the
main worker's table is untouched.

Fail-fast, as there: no `getattr` default for `JOB_TYPE`/`handle` (a module that forgets either is an
`AttributeError` at import), a `JOB_TYPE` that is not in `app.infra.jobs.JOB_TYPES` is a
`PermanentError` naming the module and the value, and so is a `JOB_TYPE` claimed by two modules and a
`STATEMENT_TIMEOUT` that is not a Postgres duration (`5s`, `250ms`, `3min`) or is zero (which Postgres
reads as 'no timeout').

The discovery is written out again rather than shared: `web/handlers/__init__.py` reads its own
`__path__` and `__name__`, and that module is not this card's to change.
"""

from __future__ import annotations

import importlib
import pkgutil
import re
from types import ModuleType

from app.infra.errors import PermanentError
from app.infra.jobs import JOB_TYPES
from app.infra.worker import Handler

_STATEMENT_TIMEOUT_RE = re.compile(r"^(\d+)(ms|s|min)$")


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
    """Every module's `STATEMENT_TIMEOUT`, keyed by `JOB_TYPE`, for the modules that declare one."""
    timeouts: dict[str, str] = {}
    for module in _load_modules():
        statement_timeout = getattr(module, "STATEMENT_TIMEOUT", None)
        if statement_timeout is None:
            continue
        match = (
            _STATEMENT_TIMEOUT_RE.fullmatch(statement_timeout)
            if isinstance(statement_timeout, str)
            else None
        )
        if match is None:
            raise PermanentError(
                f"{module.__name__}: STATEMENT_TIMEOUT must be a string matching "
                f"{_STATEMENT_TIMEOUT_RE.pattern!r} (Postgres duration form, e.g. "
                f"'5s'), got {statement_timeout!r}"
            )
        if int(match.group(1)) == 0:
            raise PermanentError(
                f"{module.__name__}: STATEMENT_TIMEOUT {statement_timeout!r} is zero, "
                "which Postgres reads as 'no timeout'"
            )
        timeouts[module.JOB_TYPE] = statement_timeout
    return timeouts
