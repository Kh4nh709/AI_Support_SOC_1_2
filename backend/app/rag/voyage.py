"""The Voyage AI REST client: embeddings and rerank (P14-T05, DEC-213, spec §5.3 and §5.5).

Two calls over `httpx`, no SDK. The shapes are Voyage's API reference's (docs.voyageai.com, checked
04/11/2026) and are pinned by recorded replies in `test_rag_voyage.py`:

    POST {VOYAGE_BASE_URL}/embeddings
        {"input": [text, ...], "model": RAG_EMBED_MODEL, "input_type": "query"|"document",
         "output_dimension": RAG_EMBED_DIMS}
        -> {"object": "list", "data": [{"object": "embedding", "embedding": [float, ...], "index": i},
            ...], "model": ..., "usage": {"total_tokens": n}}
    POST {VOYAGE_BASE_URL}/rerank
        {"query": text, "documents": [text, ...], "model": RAG_RERANK_MODEL, "top_k": len(documents),
         "truncation": true}
        -> {"object": "list", "data": [{"index": i, "relevance_score": s}, ...], "model": ...,
            "usage": {"total_tokens": n}}

Both send `Authorization: Bearer <VOYAGE_API_KEY>` and wait at most `VOYAGE_TIMEOUT_S` for each part of the
exchange. Neither retries: the caller (a job, a lookup) decides, because only it knows how long it may
still wait.

**What a failure is.** Every failure is a `RagUnavailable` with one of the closed kinds of
`rag.failures` and nothing else: 429 `rate_limit`; 401 and 403 `auth`; 402 `quota`; any
`httpx.TimeoutException` `timeout`; any other transport error, any other status that is not a success and
a body that is not what the reference says `provider_error`. What the provider wrote is not kept: the
exception is raised `from None`, and nothing here prints a body or a header (spec §5.5). An empty
`VOYAGE_API_KEY` is `auth` and sends nothing, not even a connection (spec §5.6).

**A vector is trusted only when it is whole.** The reply's items are put in the order of each item's
`index`, not of the reply, and the reply must hold every index from 0 to n-1 exactly once, each with
`RAG_EMBED_DIMS` finite numbers (Review Focus 1): a vector in the wrong place, or one of the wrong size,
would be stored against the wrong entry or searched in the wrong space without any error. A rerank reply is
read more loosely, because a score is only a number to compare: an item with an index that was not sent,
a repeated index, or a score that is not a number in [0, 1] is dropped, and the count of what was dropped
is a log line, `{"voyage_rerank_dropped": n}`.
"""

from __future__ import annotations

import json
import math
import time
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Literal

import httpx

from app.infra.config import Config
from app.rag.failures import RagUnavailable

VOYAGE_TIMEOUT_S = 15

INPUT_TYPES = ("query", "document")

_PER_MILLION = 1_000_000


@dataclass(frozen=True)
class Usage:
    """What one call cost: the tokens the reply reports, the model that was asked and how long the call
    took on this side."""

    total_tokens: int
    model: str
    latency_ms: int


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def _is_index(value: Any, size: int) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value < size


def _refuse_a_bare_string(value: Any, name: str) -> None:
    """A `str` is a `Sequence[str]`, so `embed("abc")` would be sent as three one-letter inputs and come
    back with three vectors that look right. Only a list (or tuple, or any iterable) of texts is taken.
    """
    if isinstance(value, (str, bytes)):
        raise TypeError(f"{name}: must be a sequence of strings, not a single string")


def has_key(cfg: Config) -> bool:
    """Whether a call can be made at all: `VOYAGE_API_KEY` is not empty or blank. Without one every call is
    `auth` before any request is built (`_require_key`), so a caller that records what it sent (the lookup's
    run row) asks this first."""
    return bool(cfg.VOYAGE_API_KEY.strip())


def _require_key(cfg: Config) -> str:
    if not has_key(cfg):
        raise RagUnavailable("auth")
    return cfg.VOYAGE_API_KEY.strip()


def _post(path: str, payload: dict[str, Any], cfg: Config, client: httpx.Client | None):
    """POST `payload` to `{VOYAGE_BASE_URL}{path}` and return (the reply's JSON object, latency in ms).
    A client that was given is used as it is and left open; one made here is closed."""
    key = _require_key(cfg)
    url = cfg.VOYAGE_BASE_URL.rstrip("/") + path
    http = httpx.Client(timeout=VOYAGE_TIMEOUT_S) if client is None else client
    started = time.monotonic()
    try:
        response = http.post(
            url,
            json=payload,
            headers={"Authorization": f"Bearer {key}"},
            timeout=VOYAGE_TIMEOUT_S,  # also on a client that was given with a different one
        )
    except httpx.TimeoutException:
        raise RagUnavailable("timeout") from None
    except (httpx.HTTPError, httpx.InvalidURL):
        raise RagUnavailable("provider_error") from None
    finally:
        if client is None:
            http.close()
    latency_ms = int((time.monotonic() - started) * 1000)

    status = response.status_code
    if status == 429:
        raise RagUnavailable("rate_limit")
    if status in (401, 403):
        raise RagUnavailable("auth")
    if status == 402:
        raise RagUnavailable("quota")
    if not 200 <= status < 300:
        raise RagUnavailable("provider_error")
    try:
        body = response.json()
    except ValueError:
        raise RagUnavailable("provider_error") from None
    if not isinstance(body, dict):
        raise RagUnavailable("provider_error")
    return body, latency_ms


def _tokens(body: dict[str, Any]) -> int:
    usage = body.get("usage")
    tokens = usage.get("total_tokens") if isinstance(usage, dict) else None
    if isinstance(tokens, bool) or not isinstance(tokens, int) or tokens < 0:
        raise RagUnavailable("provider_error")
    return tokens


def _vectors(body: dict[str, Any], count: int, dims: int) -> list[list[float]]:
    """The reply's vectors in input order, or `provider_error` unless there is exactly one per input,
    found by its `index`, of exactly `dims` finite numbers."""
    items = body.get("data")
    if not isinstance(items, list) or len(items) != count:
        raise RagUnavailable("provider_error")
    found: list[list[float] | None] = [None] * count
    for item in items:
        if not isinstance(item, dict):
            raise RagUnavailable("provider_error")
        index = item.get("index")
        if not _is_index(index, count) or found[index] is not None:
            raise RagUnavailable("provider_error")
        vector = item.get("embedding")
        if not isinstance(vector, list) or len(vector) != dims:
            raise RagUnavailable("provider_error")
        if not all(_is_number(x) for x in vector):
            raise RagUnavailable("provider_error")
        found[index] = [float(x) for x in vector]
    # `count` items with `count` different indices in range: every slot is filled
    return [vector for vector in found if vector is not None]


def embed(
    texts: Sequence[str],
    *,
    input_type: Literal["query", "document"],
    cfg: Config,
    client: httpx.Client | None = None,
) -> tuple[list[list[float]], Usage]:
    """One vector of `RAG_EMBED_DIMS` numbers per text, in the texts' order, and what the call cost.
    `input_type` is `document` for an entry's digest and `query` for a fingerprint. No texts is no
    request (but an empty key is still `auth`)."""
    if input_type not in INPUT_TYPES:
        raise ValueError(f"input_type: must be one of {'|'.join(INPUT_TYPES)}, got {input_type!r}")
    _refuse_a_bare_string(texts, "texts")
    inputs = list(texts)
    if not all(isinstance(text, str) for text in inputs):
        raise ValueError("texts: every text must be a string")
    _require_key(cfg)
    if not inputs:
        return [], Usage(0, cfg.RAG_EMBED_MODEL, 0)
    body, latency_ms = _post(
        "/embeddings",
        {
            "input": inputs,
            "model": cfg.RAG_EMBED_MODEL,
            "input_type": input_type,
            "output_dimension": cfg.RAG_EMBED_DIMS,
        },
        cfg,
        client,
    )
    vectors = _vectors(body, len(inputs), cfg.RAG_EMBED_DIMS)
    return vectors, Usage(_tokens(body), cfg.RAG_EMBED_MODEL, latency_ms)


def rerank(
    query: str,
    documents: Sequence[str],
    *,
    cfg: Config,
    client: httpx.Client | None = None,
) -> tuple[dict[int, float], Usage]:
    """`{index of a document: relevance score in [0, 1]}` for the documents the reply scored properly,
    and what the call cost. An item with an index that was not sent, a repeated index, or a score that is
    not a number in [0, 1] is dropped and counted in the log. No documents is no request."""
    _refuse_a_bare_string(documents, "documents")
    docs = list(documents)
    if not isinstance(query, str) or not all(isinstance(doc, str) for doc in docs):
        raise ValueError("query and documents: every text must be a string")
    _require_key(cfg)
    if not docs:
        return {}, Usage(0, cfg.RAG_RERANK_MODEL, 0)
    body, latency_ms = _post(
        "/rerank",
        {
            "query": query,
            "documents": docs,
            "model": cfg.RAG_RERANK_MODEL,
            "top_k": len(docs),
            "truncation": True,
        },
        cfg,
        client,
    )
    items = body.get("data")
    if not isinstance(items, list):
        raise RagUnavailable("provider_error")
    tokens = _tokens(body)
    scores: dict[int, float] = {}
    dropped = 0
    for item in items:
        index = item.get("index") if isinstance(item, dict) else None
        score = item.get("relevance_score") if isinstance(item, dict) else None
        if (
            not _is_index(index, len(docs))
            or index in scores
            or not _is_number(score)
            or not 0 <= score <= 1
        ):
            dropped += 1
            continue
        scores[index] = float(score)
    if dropped:
        print(json.dumps({"voyage_rerank_dropped": dropped}))
    return scores, Usage(tokens, cfg.RAG_RERANK_MODEL, latency_ms)


def cost_usd(embed_tokens: int, rerank_tokens: int, cfg: Config) -> float:
    """The tokens at the two prices of the config (USD per million), rounded to 5 decimals."""
    total = (
        embed_tokens * cfg.VOYAGE_PRICE_EMBED_PER_M + rerank_tokens * cfg.VOYAGE_PRICE_RERANK_PER_M
    )
    return round(total / _PER_MILLION, 5)
