"""P14-T05 / DEC-213, spec §5.3 and §5.5 — `rag.voyage`: the Voyage REST client (embeddings and rerank)
and `rag.failures`, the closed kinds a failure of it can have.

No network and no real key: every test runs the client over an `httpx.MockTransport` that answers with
the documented response shapes of Voyage's API reference (docs.voyageai.com, checked 04/11/2026):

    POST {base}/embeddings   body  {"input": [...], "model", "input_type", "output_dimension"}
                             reply {"object": "list", "data": [{"object": "embedding",
                                    "embedding": [floats], "index": i}, ...], "model",
                                    "usage": {"total_tokens": n}}
    POST {base}/rerank       body  {"query", "documents", "model", "top_k", "truncation": true}
                             reply {"object": "list", "data": [{"index": i, "relevance_score": s}, ...],
                                    "model", "usage": {"total_tokens": n}}

What the tests hold the client to:

* the vectors are put in the order of each item's `index`, not of the reply; a missing or repeated or
  out-of-range index, a missing item and a vector whose length is not `RAG_EMBED_DIMS` are
  `provider_error` (Review Focus 1: a wrong vector in the right place is the worst failure there is);
* 429 `rate_limit`; 401 and 403 `auth`; 402 `quota`; a timeout `timeout`; any other transport error, 5xx,
  other 4xx and a malformed body `provider_error`;
* an empty `VOYAGE_API_KEY` is `auth` and sends nothing;
* what the provider wrote is never in `str(exc)`, in the chain of the exception or in the log;
* a rerank result with an unknown index or a score outside [0, 1] is dropped and counted in the log.
"""

from __future__ import annotations

import dataclasses
import json

import httpx
import pytest
from app.infra.config import Config
from app.rag import failures, voyage
from app.rag.failures import FAILURE_KINDS, TRANSIENT_KINDS, RagUnavailable

DIMS = 256
KEY = "test-key-not-a-real-voyage-key"
CFG = Config(
    VOYAGE_API_KEY=KEY,
    VOYAGE_BASE_URL="https://voyage.test/v1",
    RAG_EMBED_DIMS=DIMS,
)
PROVIDER_WORDS = "PROVIDER-WORDS-THAT-MUST-NEVER-BE-STORED-OR-SHOWN"


def vec(seed: int, dims: int = DIMS) -> list[float]:
    """A vector of `dims` numbers whose first one says which one it is."""
    return [float(seed)] + [0.5] * (dims - 1)


def embed_reply(
    n: int,
    *,
    order: list[int] | None = None,
    dims: int = DIMS,
    tokens: int = 21,
    model: str = "voyage-4",
) -> dict:
    """The documented reply for `n` inputs; `order` is the order of the items in `data`."""
    indices = order if order is not None else list(range(n))
    return {
        "object": "list",
        "data": [{"object": "embedding", "embedding": vec(i, dims), "index": i} for i in indices],
        "model": model,
        "usage": {"total_tokens": tokens},
    }


def rerank_reply(pairs: list[tuple[object, object]], *, tokens: int = 55) -> dict:
    """The documented rerank reply: (index, relevance_score) pairs, as given."""
    return {
        "object": "list",
        "data": [{"index": i, "relevance_score": s} for i, s in pairs],
        "model": "rerank-2.5",
        "usage": {"total_tokens": tokens},
    }


class Server:
    """A MockTransport handler that answers with `reply` (or raises it) and keeps every request."""

    def __init__(self, reply: object = None, *, status: int = 200) -> None:
        self.reply = reply
        self.status = status
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if isinstance(self.reply, Exception):
            raise self.reply
        if isinstance(self.reply, (bytes, str)):
            return httpx.Response(self.status, content=self.reply)
        return httpx.Response(self.status, json=self.reply)

    @property
    def client(self) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self))

    def body(self, index: int = 0) -> dict:
        return json.loads(self.requests[index].content)


def embed(server: Server, texts=("a", "b", "c"), *, cfg: Config = CFG, input_type="document"):
    return voyage.embed(texts, input_type=input_type, cfg=cfg, client=server.client)


def rerank(server: Server, documents=("a", "b", "c"), *, cfg: Config = CFG):
    return voyage.rerank("the fingerprint", documents, cfg=cfg, client=server.client)


# ── the closed kinds ──────────────────────────────────────────────────────────────────────────


def test_the_failure_kinds_are_the_six_in_the_constraints_order() -> None:
    assert FAILURE_KINDS == (
        "rate_limit",
        "timeout",
        "auth",
        "quota",
        "provider_error",
        "vectordb_unreachable",
    )
    assert TRANSIENT_KINDS == frozenset(
        {"rate_limit", "timeout", "provider_error", "vectordb_unreachable"}
    )
    assert TRANSIENT_KINDS < set(FAILURE_KINDS) and {"auth", "quota"}.isdisjoint(TRANSIENT_KINDS)
    assert failures.FAILURE_KINDS is FAILURE_KINDS


@pytest.mark.parametrize("kind", FAILURE_KINDS)
def test_a_failure_is_its_kind_and_nothing_else(kind) -> None:
    exc = RagUnavailable(kind)
    assert exc.kind == kind and str(exc) == kind and exc.args == (kind,)
    assert isinstance(exc, Exception)


def test_a_kind_outside_the_six_is_refused() -> None:
    with pytest.raises(ValueError, match="kind"):
        RagUnavailable("the provider said no")


# ── embed: the request ────────────────────────────────────────────────────────────────────────


def test_embed_posts_the_documented_body_with_the_bearer_key() -> None:
    server = Server(embed_reply(3))
    embed(server, ("một", "hai", "ba"), input_type="query")

    (request,) = server.requests
    assert request.method == "POST" and str(request.url) == "https://voyage.test/v1/embeddings"
    assert request.headers["authorization"] == f"Bearer {KEY}"
    assert server.body() == {
        "input": ["một", "hai", "ba"],
        "model": "voyage-4",
        "input_type": "query",
        "output_dimension": DIMS,
    }


def test_embed_uses_the_configured_model_dims_and_base_url() -> None:
    cfg = dataclasses.replace(
        CFG,
        RAG_EMBED_MODEL="voyage-4-lite",
        RAG_EMBED_DIMS=512,
        VOYAGE_BASE_URL="https://v.test/x/",
    )
    server = Server(embed_reply(1, dims=512))
    embed(server, ("a",), cfg=cfg)
    assert str(server.requests[0].url) == "https://v.test/x/embeddings"  # no double slash
    assert server.body()["model"] == "voyage-4-lite" and server.body()["output_dimension"] == 512


@pytest.mark.parametrize("input_type", ["", "search", None, "QUERY"])
def test_embed_refuses_an_input_type_voyage_does_not_have(input_type) -> None:
    server = Server(embed_reply(1))
    with pytest.raises(ValueError, match="input_type"):
        embed(server, ("a",), input_type=input_type)
    assert server.requests == []


def test_embed_of_nothing_sends_nothing() -> None:
    server = Server(embed_reply(0))
    vectors, usage = embed(server, ())
    assert vectors == [] and usage.total_tokens == 0 and server.requests == []


def test_every_request_is_bounded_by_the_timeout_even_on_a_client_that_has_none() -> None:
    server = Server(embed_reply(1))
    embed(server, ("a",))
    assert voyage.VOYAGE_TIMEOUT_S == 15
    timeout = server.requests[0].extensions["timeout"]
    assert timeout == {"connect": 15, "read": 15, "write": 15, "pool": 15}


def test_a_client_of_its_own_is_made_with_the_timeout_and_closed(monkeypatch) -> None:
    server = Server(embed_reply(1))
    made: list[tuple[httpx.Client, dict]] = []
    real = httpx.Client

    def factory(**kwargs):
        client = real(transport=httpx.MockTransport(server))
        made.append((client, kwargs))
        return client

    monkeypatch.setattr(voyage.httpx, "Client", factory)
    voyage.embed(["a"], input_type="document", cfg=CFG)

    ((client, kwargs),) = made
    assert kwargs["timeout"] == 15 and client.is_closed


def test_a_client_that_was_given_is_left_open() -> None:
    server = Server(embed_reply(1))
    client = server.client
    voyage.embed(["a"], input_type="document", cfg=CFG, client=client)
    assert not client.is_closed
    client.close()


# ── embed: the answer (Review Focus 1) ────────────────────────────────────────────────────────


@pytest.mark.parametrize("order", [[2, 0, 3, 1], [3, 2, 1, 0], [1, 0, 2, 3], [0, 1, 3, 2]])
def test_vectors_are_mapped_by_index_not_by_position(order) -> None:
    server = Server(embed_reply(4, order=order))
    vectors, usage = embed(server, ("a", "b", "c", "d"))
    assert [v[0] for v in vectors] == [0.0, 1.0, 2.0, 3.0]  # vec(i) starts with i
    assert all(len(v) == DIMS for v in vectors)
    assert usage.total_tokens == 21


def test_the_usage_is_the_replys_tokens_the_configured_model_and_a_latency() -> None:
    _, usage = embed(Server(embed_reply(1, tokens=7)), ("a",))
    assert usage.total_tokens == 7 and usage.model == "voyage-4"
    assert isinstance(usage.latency_ms, int) and usage.latency_ms >= 0
    with pytest.raises(dataclasses.FrozenInstanceError):
        usage.total_tokens = 8  # type: ignore[misc]


@pytest.mark.parametrize(
    "order",
    [
        [0, 2],  # index 1 is missing
        [0, 1],  # the last one is missing
        [0, 0, 2],  # 0 twice, 1 missing
        [0, 1, 1],  # 1 twice
        [0, 1, 3],  # 3 is out of range for 3 inputs
        [1, 2, 3],  # shifted by one
        [-1, 0, 1],  # negative
        [0, 1, 2, 2],  # one more item than inputs
        [],
    ],
)
def test_a_missing_repeated_or_out_of_range_index_is_provider_error(order) -> None:
    server = Server(embed_reply(3, order=order))
    with pytest.raises(RagUnavailable) as caught:
        embed(server)
    assert caught.value.kind == "provider_error"


@pytest.mark.parametrize("index", ["1", 1.0, None, True, [1]])
def test_an_index_that_is_not_an_integer_is_provider_error(index) -> None:
    reply = embed_reply(2)
    reply["data"][1]["index"] = index
    with pytest.raises(RagUnavailable) as caught:
        embed(Server(reply), ("a", "b"))
    assert caught.value.kind == "provider_error"


@pytest.mark.parametrize("length", [0, 1, DIMS - 1, DIMS + 1, 1024])
def test_a_vector_of_another_length_than_the_configured_dims_is_provider_error(length) -> None:
    reply = embed_reply(2)
    reply["data"][1]["embedding"] = [0.25] * length
    with pytest.raises(RagUnavailable) as caught:
        embed(Server(reply), ("a", "b"))
    assert caught.value.kind == "provider_error"


@pytest.mark.parametrize(
    "bad",
    [None, "0.1", [0.1] * (DIMS - 1) + [None], [0.1] * (DIMS - 1) + ["x"], [True] * DIMS, 5],
)
def test_a_vector_that_is_not_numbers_is_provider_error(bad) -> None:
    reply = embed_reply(1)
    reply["data"][0]["embedding"] = bad
    with pytest.raises(RagUnavailable) as caught:
        embed(Server(reply), ("a",))
    assert caught.value.kind == "provider_error"


@pytest.mark.parametrize("number", [float("nan"), float("inf"), float("-inf")])
def test_a_vector_with_a_number_pgvector_would_refuse_is_provider_error(number) -> None:
    reply = embed_reply(1)
    reply["data"][0]["embedding"][5] = number
    server = Server(json.dumps(reply, allow_nan=True))  # Python's json writes NaN; so can a proxy
    with pytest.raises(RagUnavailable) as caught:
        embed(server, ("a",))
    assert caught.value.kind == "provider_error"


@pytest.mark.parametrize(
    "mutate",
    [
        lambda r: r.pop("data"),
        lambda r: r.update(data=None),
        lambda r: r.update(data={"0": 1}),
        lambda r: r.update(data=[1]),
        lambda r: r["data"][0].pop("embedding"),
        lambda r: r["data"][0].pop("index"),
        lambda r: r.pop("usage"),
        lambda r: r.update(usage={}),
        lambda r: r.update(usage={"total_tokens": "21"}),
        lambda r: r.update(usage={"total_tokens": -1}),
        lambda r: r.update(usage={"total_tokens": True}),
    ],
)
def test_a_malformed_body_is_provider_error(mutate) -> None:
    reply = embed_reply(1)
    mutate(reply)
    with pytest.raises(RagUnavailable) as caught:
        embed(Server(reply), ("a",))
    assert caught.value.kind == "provider_error"


@pytest.mark.parametrize("body", ["", "not json", "[]", "null", "42", '"text"', "{"])
def test_a_body_that_is_not_a_json_object_is_provider_error(body) -> None:
    with pytest.raises(RagUnavailable) as caught:
        embed(Server(body), ("a",))
    assert caught.value.kind == "provider_error"


# ── the failures: one kind each (both calls) ──────────────────────────────────────────────────

STATUS_KINDS = [
    (429, "rate_limit"),
    (401, "auth"),
    (403, "auth"),
    (402, "quota"),
    (500, "provider_error"),
    (502, "provider_error"),
    (503, "provider_error"),
    (504, "provider_error"),
    (400, "provider_error"),
    (404, "provider_error"),
    (408, "provider_error"),
    (413, "provider_error"),
    (422, "provider_error"),
    (301, "provider_error"),  # a redirect is followed by nobody: the key must not leave with it
    (204, "provider_error"),  # a success with no body is a malformed one
]
CALLS = {"embed": embed, "rerank": rerank}


@pytest.mark.parametrize("call", CALLS)
@pytest.mark.parametrize(("status", "kind"), STATUS_KINDS)
def test_an_http_status_is_its_kind(call, status, kind) -> None:
    server = Server({"detail": PROVIDER_WORDS}, status=status)
    with pytest.raises(RagUnavailable) as caught:
        CALLS[call](server)
    assert caught.value.kind == kind
    assert len(server.requests) == 1  # no retry inside the client: the job and the lookup decide


@pytest.mark.parametrize("call", CALLS)
@pytest.mark.parametrize("status", [500, 502, 400, 404, 301])
def test_a_failure_status_is_a_failure_even_with_a_good_looking_body(call, status) -> None:
    """The status decides first: a gateway that answers 502 with a cached good body is not an answer."""
    reply = embed_reply(3) if call == "embed" else rerank_reply([(0, 0.9), (1, 0.5), (2, 0.1)])
    with pytest.raises(RagUnavailable) as caught:
        CALLS[call](Server(reply, status=status))
    assert caught.value.kind == "provider_error"


@pytest.mark.parametrize("call", CALLS)
@pytest.mark.parametrize(
    "error",
    [
        httpx.ReadTimeout("slow"),
        httpx.ConnectTimeout("slow"),
        httpx.WriteTimeout("slow"),
        httpx.PoolTimeout("slow"),
    ],
)
def test_a_timeout_is_timeout(call, error) -> None:
    with pytest.raises(RagUnavailable) as caught:
        CALLS[call](Server(error))
    assert caught.value.kind == "timeout"


@pytest.mark.parametrize("call", CALLS)
@pytest.mark.parametrize(
    "error",
    [
        httpx.ConnectError("refused"),
        httpx.ReadError("reset"),
        httpx.RemoteProtocolError("bad frame"),
        httpx.UnsupportedProtocol("no scheme"),
        httpx.InvalidURL("bad url"),
    ],
)
def test_any_other_transport_error_is_provider_error(call, error) -> None:
    with pytest.raises(RagUnavailable) as caught:
        CALLS[call](Server(error))
    assert caught.value.kind == "provider_error"


@pytest.mark.parametrize("call", CALLS)
def test_a_bug_in_our_own_code_is_not_a_provider_error(call) -> None:
    """Only what `httpx` can raise from the network is a kind; a `KeyError` must stay visible."""
    with pytest.raises(KeyError):
        CALLS[call](Server(KeyError("ours")))


@pytest.mark.parametrize("call", CALLS)
@pytest.mark.parametrize("status", [401, 402, 429, 500])
def test_what_the_provider_wrote_is_in_no_message_chain_or_log(
    call, status, capsys, caplog
) -> None:
    caplog.set_level("DEBUG")
    server = Server({"error": {"message": PROVIDER_WORDS}, "detail": PROVIDER_WORDS}, status=status)
    with pytest.raises(RagUnavailable) as caught:
        CALLS[call](server)
    exc = caught.value
    seen = capsys.readouterr()
    text = " ".join([str(exc), repr(exc), seen.out, seen.err, caplog.text])
    assert PROVIDER_WORDS not in text and KEY not in text
    assert str(exc) == exc.kind
    assert exc.__cause__ is None and (exc.__context__ is None or exc.__suppress_context__)


@pytest.mark.parametrize("call", CALLS)
def test_a_transport_errors_words_are_not_kept_either(call, capsys) -> None:
    server = Server(httpx.ConnectError(f"connect to {PROVIDER_WORDS} failed"))
    with pytest.raises(RagUnavailable) as caught:
        CALLS[call](server)
    exc = caught.value
    assert PROVIDER_WORDS not in str(exc) + repr(exc) + capsys.readouterr().out
    assert exc.__cause__ is None and exc.__suppress_context__


# ── an empty key sends nothing (spec §5.6) ────────────────────────────────────────────────────


@pytest.mark.parametrize("call", CALLS)
@pytest.mark.parametrize("key", ["", "   "])
def test_an_empty_key_is_auth_and_sends_no_request(call, key) -> None:
    server = Server(embed_reply(3))
    cfg = dataclasses.replace(CFG, VOYAGE_API_KEY=key)
    with pytest.raises(RagUnavailable) as caught:
        CALLS[call](server, cfg=cfg)
    assert caught.value.kind == "auth" and str(caught.value) == "auth"
    assert server.requests == []


@pytest.mark.parametrize("call", ["embed", "rerank"])
def test_an_empty_key_does_not_even_build_a_client(call, monkeypatch) -> None:
    def boom(**kwargs):
        raise AssertionError("an httpx.Client was built for a call that has no key")

    monkeypatch.setattr(voyage.httpx, "Client", boom)
    cfg = dataclasses.replace(CFG, VOYAGE_API_KEY="")
    with pytest.raises(RagUnavailable) as caught:
        if call == "embed":
            voyage.embed(["a"], input_type="query", cfg=cfg)
        else:
            voyage.rerank("q", ["a"], cfg=cfg)
    assert caught.value.kind == "auth"


def test_an_empty_key_wins_over_an_empty_list() -> None:
    cfg = dataclasses.replace(CFG, VOYAGE_API_KEY="")
    with pytest.raises(RagUnavailable) as caught:
        voyage.embed([], input_type="query", cfg=cfg)
    assert caught.value.kind == "auth"


# ── rerank ────────────────────────────────────────────────────────────────────────────────────


def test_rerank_posts_the_documented_body() -> None:
    server = Server(rerank_reply([(0, 0.9), (1, 0.2), (2, 0.5)]))
    rerank(server, ("một", "hai", "ba"))

    (request,) = server.requests
    assert request.method == "POST" and str(request.url) == "https://voyage.test/v1/rerank"
    assert request.headers["authorization"] == f"Bearer {KEY}"
    assert server.body() == {
        "query": "the fingerprint",
        "documents": ["một", "hai", "ba"],
        "model": "rerank-2.5",
        "top_k": 3,
        "truncation": True,
    }
    assert request.extensions["timeout"]["read"] == 15


def test_rerank_returns_the_score_of_each_index_whatever_the_order() -> None:
    server = Server(rerank_reply([(2, 0.91), (0, 0.5), (1, 0.0)], tokens=77))
    scores, usage = rerank(server)
    assert scores == {0: 0.5, 1: 0.0, 2: 0.91}
    assert usage.total_tokens == 77 and usage.model == "rerank-2.5" and usage.latency_ms >= 0


def test_rerank_scores_of_exactly_zero_and_one_are_kept() -> None:
    scores, _ = rerank(Server(rerank_reply([(0, 1), (1, 0), (2, 1.0)])))
    assert scores == {0: 1.0, 1: 0.0, 2: 1.0}


def test_rerank_of_nothing_sends_nothing() -> None:
    server = Server(rerank_reply([]))
    scores, usage = rerank(server, ())
    assert scores == {} and usage.total_tokens == 0 and server.requests == []


def dropped_in(log: str) -> list[int]:
    """The `n` of every `{"voyage_rerank_dropped": n}` line of the log."""
    counts = []
    for line in log.splitlines():
        try:
            payload = json.loads(line)
        except ValueError:
            continue
        if isinstance(payload, dict) and "voyage_rerank_dropped" in payload:
            counts.append(payload["voyage_rerank_dropped"])
    return counts


@pytest.mark.parametrize(
    ("pairs", "kept", "dropped"),
    [
        ([(0, 0.8), (3, 0.9)], {0: 0.8}, 1),  # index 3 was never sent
        ([(0, 0.8), (-1, 0.9)], {0: 0.8}, 1),
        ([(0, 0.8), (1, 1.5)], {0: 0.8}, 1),  # above 1
        ([(0, 0.8), (1, -0.01)], {0: 0.8}, 1),  # below 0
        ([(0, 0.8), (0, 0.3)], {0: 0.8}, 1),  # a repeat: the first one stays
        ([(0, 0.8), ("1", 0.5), (1.0, 0.5), (None, 0.5), (True, 0.5)], {0: 0.8}, 4),
        ([(0, 0.8), (1, "0.5"), (2, None), (2, True)], {0: 0.8}, 3),
        ([(9, 2.0), (8, -2.0), (0, 0.4)], {0: 0.4}, 2),
    ],
)
def test_an_unknown_index_or_a_score_outside_zero_one_is_dropped_and_counted(
    pairs, kept, dropped, capsys
) -> None:
    scores, _ = rerank(Server(rerank_reply(pairs)))
    assert scores == kept
    assert dropped_in(capsys.readouterr().out) == [dropped]


def test_a_clean_rerank_logs_no_drop(capsys) -> None:
    rerank(Server(rerank_reply([(0, 0.8), (1, 0.1), (2, 0.5)])))
    assert dropped_in(capsys.readouterr().out) == []


def test_a_nan_score_is_dropped(capsys) -> None:
    server = Server(
        '{"object":"list","data":[{"index":0,"relevance_score":NaN},'
        '{"index":1,"relevance_score":0.5}],"model":"rerank-2.5",'
        '"usage":{"total_tokens":3}}'
    )
    scores, _ = rerank(server, ("a", "b"))
    assert scores == {1: 0.5} and dropped_in(capsys.readouterr().out) == [1]


@pytest.mark.parametrize(
    "mutate",
    [
        lambda r: r.pop("data"),
        lambda r: r.update(data=None),
        lambda r: r.update(data="0.5"),
        lambda r: r.update(data={"0": 1}),
        lambda r: r.pop("usage"),
        lambda r: r.update(usage={"total_tokens": "55"}),
        lambda r: r.update(usage={"total_tokens": -5}),
    ],
)
def test_a_malformed_rerank_body_is_provider_error(mutate) -> None:
    reply = rerank_reply([(0, 0.5)])
    mutate(reply)
    with pytest.raises(RagUnavailable) as caught:
        rerank(Server(reply), ("a",))
    assert caught.value.kind == "provider_error"


# ── cost_usd ──────────────────────────────────────────────────────────────────────────────────


def test_cost_is_the_tokens_at_the_two_prices_rounded_to_five_decimals() -> None:
    assert voyage.cost_usd(0, 0, CFG) == 0.0
    assert voyage.cost_usd(1_000_000, 0, CFG) == 0.06
    assert voyage.cost_usd(0, 1_000_000, CFG) == 0.05
    assert voyage.cost_usd(1_000_000, 1_000_000, CFG) == 0.11
    # 123456 * 0.06 / 1e6 = 0.00740736 and 654321 * 0.05 / 1e6 = 0.03271605: 0.04012341 -> 0.04012
    assert voyage.cost_usd(123_456, 654_321, CFG) == 0.04012
    assert voyage.cost_usd(300, 0, CFG) == 0.00002  # 0.000018: the lab's approval-time embedding


def test_cost_reads_the_prices_from_the_config() -> None:
    cfg = dataclasses.replace(CFG, VOYAGE_PRICE_EMBED_PER_M=2.0, VOYAGE_PRICE_RERANK_PER_M=10.0)
    assert voyage.cost_usd(500_000, 100_000, cfg) == 2.0
    assert isinstance(voyage.cost_usd(1, 1, cfg), float)
