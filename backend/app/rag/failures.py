"""The closed kinds a Voyage call or the vector database can fail with (P14-T05, DEC-213, spec §5.3).

Six, in the order the frozen contract lists them: `rate_limit`, `timeout`, `auth`, `quota`,
`provider_error`, `vectordb_unreachable`. They are what a lookup records (`rag_results.failure_kind`,
migration 023), what the notice shows and what the health check counts. Nothing else is: a provider's
message is never stored, logged or shown (spec §5.5), so an exception here carries its kind and no more.

`TRANSIENT_KINDS` are the ones a later attempt can cure: a job that fails with one is retried
(`TransientError`), one that fails with `auth` (a key that is refused or missing) or `quota` (402, the
account has nothing left) is not (`PermanentError`): the Owner has to act, and trying again only spends
attempts.
"""

from __future__ import annotations

FAILURE_KINDS: tuple[str, ...] = (
    "rate_limit",
    "timeout",
    "auth",
    "quota",
    "provider_error",
    "vectordb_unreachable",
)

TRANSIENT_KINDS = frozenset({"rate_limit", "timeout", "provider_error", "vectordb_unreachable"})


class RagUnavailable(Exception):
    """The retrieval cannot be done right now, for one of `FAILURE_KINDS`.

    `str(exc)` is the kind and nothing else, so no log line, job `last_error` or traceback made from it
    can carry a provider's words, an address or a key. Raise it `from None`: the error underneath is a
    library's, and its text is the provider's or the network's.
    """

    def __init__(self, kind: str) -> None:
        if kind not in FAILURE_KINDS:
            raise ValueError(f"kind: must be one of {'|'.join(FAILURE_KINDS)}, got {kind!r}")
        super().__init__(kind)
        self.kind = kind
