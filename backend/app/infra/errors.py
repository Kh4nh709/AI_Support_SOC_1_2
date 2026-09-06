"""Classify exceptions transient vs permanent for job retry; unclassified defaults to transient.

Transient means the job that raised it should be retried; permanent means it
should fail now. `ConfigError` is unrelated to job retry — it is raised only by
`app.infra.config.load()` when the environment cannot be turned into a valid
`Config`, at process startup, before any job exists.
"""

from __future__ import annotations

from typing import Literal

import httpx
import psycopg

_counters: dict[str, int] = {}


class ConfigError(Exception):
    """The environment/`.env` cannot be turned into a valid `Config`."""


class TransientError(Exception):
    """The job that raised this should retry."""


class PermanentError(Exception):
    """The job that raised this fails now; it must not retry."""


def _status_code(exc: BaseException) -> int | None:
    """The HTTP status `exc` carries, directly (`exc.status_code`, e.g. a custom
    HTTP error) or nested (`exc.response.status_code`, e.g. `httpx.HTTPStatusError`)
    — or None if it carries neither."""
    direct = getattr(exc, "status_code", None)
    if isinstance(direct, int):
        return direct
    nested = getattr(getattr(exc, "response", None), "status_code", None)
    if isinstance(nested, int):
        return nested
    return None


def classify(exc: BaseException) -> Literal["transient", "permanent"]:
    if isinstance(exc, (TransientError, psycopg.OperationalError, httpx.TransportError)):
        return "transient"
    if isinstance(
        exc,
        (
            PermanentError,
            psycopg.DataError,
            psycopg.IntegrityError,
            ValueError,
            KeyError,
            TypeError,
        ),
    ):
        return "permanent"
    status = _status_code(exc)
    if status is not None and status >= 500:
        return "transient"
    if status is not None and 400 <= status < 500:
        return "permanent"
    key = f"UNCLASSIFIED:{type(exc).__name__}"
    _counters[key] = _counters.get(key, 0) + 1
    return "transient"


def counters() -> dict[str, int]:
    """A copy of the unclassified-exception counters — callers (the worker's
    health line) must not be able to mutate the module's live state."""
    return dict(_counters)
