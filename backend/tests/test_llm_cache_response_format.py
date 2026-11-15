"""`eval/llm_cache.py` and the response format (DEC-218, JS-T1 fix round 1, minor A). PURE.

The cache key left out the format, so an evaluation run with `LLM_RESPONSE_FORMAT=json_schema` would have been
served the answers a `json_object` run recorded (and the reverse). Now:

* a request with no format, or with `{"type": "json_object"}`, has EXACTLY today's key, the one
  `smoke_test.cache_key` gives, and today's `request` record, so every entry already on disk stays a hit;
* a `json_schema` request has another key, which depends on the schema name and on the schema itself;
* an entry records the format the inner adapter reports for the answer, and a hit reports it, so a
  `json_schema` request that was answered as `json_object` (the provider refused the format) is a fallback
  on a replay as it was live; an entry that says nothing (every entry written before) reports `None`.

The reference key is computed from an independent copy of the smoke test (`smoke_ref`), never from the
module under test.
"""

from __future__ import annotations

import copy
import json

import pytest
from app.llm import schemas
from app.llm import triage as T
from app.llm.adapter import LLMResult

from tests.fakes.llm import TRIAGE_V3_TRUE_POSITIVE
from tests.test_llm_cache import (
    MODEL,
    NONCE_A,
    SYSTEM,
    CachingAdapter,
    CountingLLM,
    build_user,
    entries,
    llm_cache,
    sha256,
    smoke_ref,
)
from tests.test_llm_triage import _build, _cfg


def _format(name: str = "triage_v3") -> dict:
    return {
        "type": "json_schema",
        "json_schema": {"name": name, "strict": True, "schema": schemas.json_schema(name)},
    }


class ReportingLLM(CountingLLM):
    """`CountingLLM` whose results say which format produced them, as the real adapter's do. `reports` is the
    list of what each call reports, in order; `None` means "the format that was asked for"."""

    def __init__(self, responses, *, reports=(), **kwargs):
        super().__init__(responses, **kwargs)
        self._reports = list(reports)

    def complete(self, *, system, user, response_format=None, timeout_s=None, model=None):
        index = len(self.calls)
        got = super().complete(
            system=system,
            user=user,
            response_format=response_format,
            timeout_s=timeout_s,
            model=model,
        )
        reported = self._reports[index] if index < len(self._reports) else None
        asked = (response_format or {"type": "json_object"})["type"]
        return LLMResult(
            content=got.content,
            model=got.model,
            usage=got.usage,
            latency_ms=got.latency_ms,
            response_format=reported or asked,
        )


def _cache(tmp_path, inner, thinking="disabled"):
    return CachingAdapter(inner, cache_dir=tmp_path, thinking=thinking)


# --------------------------------------------------------------------------------- the key


class TestTheKeyIsTodaysForJsonObject:
    """Every entry written before this change must stay valid."""

    @pytest.mark.parametrize(
        "response_format",
        [None, {"type": "json_object"}],
        ids=["no format", "json_object"],
    )
    def test_the_key_is_the_one_computed_the_old_way(self, tmp_path, response_format):
        cache = _cache(tmp_path, CountingLLM([]))
        user = build_user(NONCE_A)
        old_way = smoke_ref.cache_key(
            MODEL, SYSTEM, smoke_ref.stable_user(user, NONCE_A), "disabled"
        )

        assert (
            cache.key_for(system=SYSTEM, user=user, model=MODEL, response_format=response_format)
            == old_way
        )
        assert cache.key_for(system=SYSTEM, user=user, model=MODEL) == old_way  # the old call shape

    @pytest.mark.parametrize("response_format", [None, {"type": "json_object"}])
    def test_a_request_goes_to_the_old_key_and_the_old_request_record(
        self, tmp_path, response_format
    ):
        inner = CountingLLM(['{"answer": 1}'])
        cache = _cache(tmp_path, inner)
        user = build_user(NONCE_A)

        live = cache.complete(
            system=SYSTEM, user=user, model=MODEL, response_format=response_format
        )

        assert live.key == smoke_ref.cache_key(
            MODEL, SYSTEM, smoke_ref.stable_user(user, NONCE_A), "disabled"
        )
        entry = json.loads((tmp_path / f"{live.key}.json").read_text("utf-8"))
        assert entry["request"] == {
            "model": MODEL,
            "thinking": "disabled",
            "system_sha256": sha256(SYSTEM),
            "user_sha256": sha256(llm_cache.fold_nonce(user)),
        }

    @pytest.mark.parametrize("response_format", [None, {"type": "json_object"}])
    def test_an_entry_written_before_this_change_is_still_a_hit(self, tmp_path, response_format):
        """An entry exactly as `_measure` wrote it before: no `response_format` field, the four-key request."""
        user = build_user(NONCE_A)
        key = smoke_ref.cache_key(MODEL, SYSTEM, smoke_ref.stable_user(user, NONCE_A), "disabled")
        old_entry = {
            "format": llm_cache.ENTRY_FORMAT,
            "key": key,
            "request": {
                "model": MODEL,
                "thinking": "disabled",
                "system_sha256": sha256(SYSTEM),
                "user_sha256": sha256(llm_cache.fold_nonce(user)),
            },
            "called_at": "2026-11-01T00:00:00.000+00:00",
            "content": '{"old": true}',
            "model": "deepseek-v4-flash",
            "usage": {"prompt_tokens": 7, "completion_tokens": 3},
            "latency_ms": 1234,
        }
        (tmp_path / f"{key}.json").write_text(json.dumps(old_entry), encoding="utf-8")
        inner = CountingLLM([])  # a call would raise: there is no canned answer
        cache = _cache(tmp_path, inner)

        hit = cache.complete(system=SYSTEM, user=user, model=MODEL, response_format=response_format)

        assert hit.cached is True and inner.calls == []
        assert hit.content == '{"old": true}' and hit.latency_ms == 1234
        assert hit.response_format is None  # an old entry says nothing about the format


# --------------------------------------------------------------------------------- the key, schema


class TestJsonSchemaHasItsOwnKey:
    def test_the_key_differs_from_json_object_s(self, tmp_path):
        cache = _cache(tmp_path, CountingLLM([]))
        user = build_user(NONCE_A)

        plain = cache.key_for(system=SYSTEM, user=user, model=MODEL)
        schema = cache.key_for(system=SYSTEM, user=user, model=MODEL, response_format=_format())

        assert schema != plain

    def test_the_key_is_stable_for_the_same_format(self, tmp_path):
        cache = _cache(tmp_path, CountingLLM([]))
        user = build_user(NONCE_A)

        first = cache.key_for(system=SYSTEM, user=user, model=MODEL, response_format=_format())
        second = cache.key_for(
            system=SYSTEM,
            user=build_user("fedcba9876543210"),  # another build: the nonce is folded as ever
            model=MODEL,
            response_format=copy.deepcopy(_format()),
        )

        assert first == second

    def test_the_key_depends_on_the_schema_name(self, tmp_path):
        cache = _cache(tmp_path, CountingLLM([]))
        user = build_user(NONCE_A)
        same_body = _format("triage_v3")
        same_body["json_schema"]["name"] = "another_name"

        a = cache.key_for(
            system=SYSTEM, user=user, model=MODEL, response_format=_format("triage_v3")
        )
        b = cache.key_for(system=SYSTEM, user=user, model=MODEL, response_format=same_body)
        c = cache.key_for(
            system=SYSTEM, user=user, model=MODEL, response_format=_format("verifier_v2")
        )

        assert len({a, b, c}) == 3

    def test_the_key_depends_on_the_schema_itself(self, tmp_path):
        """A schema that changes (a field added to `output_schemas.json`) is another measurement."""
        cache = _cache(tmp_path, CountingLLM([]))
        user = build_user(NONCE_A)
        edited = _format()
        edited["json_schema"]["schema"]["required"] = edited["json_schema"]["schema"]["required"][
            :-1
        ]

        a = cache.key_for(system=SYSTEM, user=user, model=MODEL, response_format=_format())
        b = cache.key_for(system=SYSTEM, user=user, model=MODEL, response_format=edited)

        assert a != b

    def test_the_other_key_inputs_still_separate_entries(self, tmp_path):
        cache = _cache(tmp_path, CountingLLM([]))
        user = build_user(NONCE_A)
        base = cache.key_for(system=SYSTEM, user=user, model=MODEL, response_format=_format())

        assert base != cache.key_for(
            system=SYSTEM + "!", user=user, model=MODEL, response_format=_format()
        )
        assert base != cache.key_for(
            system=SYSTEM, user=user, model="deepseek-v4-pro", response_format=_format()
        )
        enabled = CachingAdapter(CountingLLM([]), cache_dir=tmp_path, thinking="enabled")
        assert base != enabled.key_for(
            system=SYSTEM, user=user, model=MODEL, response_format=_format()
        )


class TestAJsonObjectEntryIsNeverServedToAJsonSchemaRun:
    def test_two_requests_two_measurements_each_replayed_from_its_own_entry(self, tmp_path):
        inner = CountingLLM(['{"mode": "json_object"}', '{"mode": "json_schema"}'])
        cache = _cache(tmp_path, inner)
        user = build_user(NONCE_A)

        plain = cache.complete(system=SYSTEM, user=user, model=MODEL)
        schema = cache.complete(system=SYSTEM, user=user, model=MODEL, response_format=_format())

        assert len(inner.calls) == 2 and len(entries(tmp_path)) == 2
        assert plain.key != schema.key and (plain.cached, schema.cached) == (False, False)
        assert inner.calls[1]["response_format"] == _format()  # the format is still passed on
        # replays
        assert (
            cache.complete(system=SYSTEM, user=user, model=MODEL).content
            == '{"mode": "json_object"}'
        )
        again = cache.complete(system=SYSTEM, user=user, model=MODEL, response_format=_format())
        assert again.content == '{"mode": "json_schema"}' and again.cached is True
        assert len(inner.calls) == 2

    def test_the_schema_entry_records_the_format_in_its_request(self, tmp_path):
        cache = _cache(tmp_path, CountingLLM(["{}"]))
        user = build_user(NONCE_A)

        live = cache.complete(system=SYSTEM, user=user, model=MODEL, response_format=_format())

        entry = json.loads((tmp_path / f"{live.key}.json").read_text("utf-8"))
        assert entry["request"]["response_format_sha256"] == sha256(
            json.dumps(_format(), sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        )
        assert set(entry["request"]) == {
            "model",
            "thinking",
            "system_sha256",
            "user_sha256",
            "response_format_sha256",
        }
        assert "triage_v3" not in json.dumps(entry)  # a digest, never the schema text

    def test_an_entry_of_another_format_filed_under_the_key_is_a_miss_not_a_hit(self, tmp_path):
        """A hand-placed json_object entry under the json_schema key (a collision, a copy) is not served."""
        user = build_user(NONCE_A)
        probe = _cache(tmp_path, CountingLLM([]))
        schema_key = probe.key_for(system=SYSTEM, user=user, model=MODEL, response_format=_format())
        plain_key = probe.key_for(system=SYSTEM, user=user, model=MODEL)
        entry = {
            "format": llm_cache.ENTRY_FORMAT,
            "key": schema_key,
            "request": {
                "model": MODEL,
                "thinking": "disabled",
                "system_sha256": sha256(SYSTEM),
                "user_sha256": sha256(llm_cache.fold_nonce(user)),
            },  # the json_object request record: no response_format_sha256
            "called_at": "2026-11-01T00:00:00.000+00:00",
            "content": '{"stale": true}',
            "model": "m",
            "usage": {},
            "latency_ms": 1,
        }
        (tmp_path / f"{schema_key}.json").write_text(json.dumps(entry), encoding="utf-8")
        inner = CountingLLM(['{"fresh": true}'])

        got = _cache(tmp_path, inner).complete(
            system=SYSTEM, user=user, model=MODEL, response_format=_format()
        )

        assert plain_key != schema_key
        assert got.cached is False and got.content == '{"fresh": true}'


# --------------------------------------------------------------------------------- what a hit reports


class TestACachedResultReportsTheFormatItWasMadeWith:
    def test_a_live_result_and_its_replay_report_what_the_inner_adapter_reported(self, tmp_path):
        inner = ReportingLLM(["{}"], reports=["json_schema"])
        cache = _cache(tmp_path, inner)
        user = build_user(NONCE_A)

        live = cache.complete(system=SYSTEM, user=user, model=MODEL, response_format=_format())
        hit = cache.complete(system=SYSTEM, user=user, model=MODEL, response_format=_format())

        assert (live.cached, hit.cached) == (False, True)
        assert live.response_format == hit.response_format == "json_schema"

    def test_a_json_schema_request_answered_as_json_object_replays_as_json_object(self, tmp_path):
        inner = ReportingLLM(["{}"], reports=["json_object"])
        cache = _cache(tmp_path, inner)
        user = build_user(NONCE_A)

        live = cache.complete(system=SYSTEM, user=user, model=MODEL, response_format=_format())
        hit = cache.complete(system=SYSTEM, user=user, model=MODEL, response_format=_format())

        assert live.response_format == hit.response_format == "json_object"
        assert hit.cached is True and len(inner.calls) == 1

    def test_an_inner_adapter_that_reports_nothing_gives_none_and_writes_no_field(self, tmp_path):
        inner = CountingLLM(["{}"])  # the fake result has no `response_format`
        cache = _cache(tmp_path, inner)
        user = build_user(NONCE_A)

        live = cache.complete(system=SYSTEM, user=user, model=MODEL)
        hit = cache.complete(system=SYSTEM, user=user, model=MODEL)

        assert live.response_format is None and hit.response_format is None
        assert "response_format" not in json.loads(
            (tmp_path / f"{live.key}.json").read_text("utf-8")
        )

    def test_a_garbled_field_in_an_entry_reads_as_none(self, tmp_path):
        inner = ReportingLLM(["{}"], reports=["json_schema"])
        cache = _cache(tmp_path, inner)
        user = build_user(NONCE_A)
        live = cache.complete(system=SYSTEM, user=user, model=MODEL, response_format=_format())
        path = tmp_path / f"{live.key}.json"
        entry = json.loads(path.read_text("utf-8"))
        entry["response_format"] = {"type": "json_schema"}  # not a string
        path.write_text(json.dumps(entry), encoding="utf-8")

        hit = cache.complete(system=SYSTEM, user=user, model=MODEL, response_format=_format())

        assert hit.cached is True and hit.response_format is None


class TestThroughProposeAndTheSwitch:
    def test_a_json_object_run_then_a_json_schema_run_are_two_measurements(self, tmp_path):
        inner = ReportingLLM([TRIAGE_V3_TRUE_POSITIVE, TRIAGE_V3_TRUE_POSITIVE])
        cache = _cache(tmp_path, inner)
        built = _build()

        off = T.propose(cache, built, cfg=_cfg())
        on = T.propose(cache, built, cfg=_cfg(LLM_RESPONSE_FORMAT="json_schema"))
        replay = T.propose(cache, built, cfg=_cfg(LLM_RESPONSE_FORMAT="json_schema"))

        assert len(inner.calls) == 2  # the schema run was not served the json_object entry
        assert [c["response_format"] for c in inner.calls] == [None, _format()]
        assert off.format_fallback is False and on.format_fallback is False
        assert replay.parsed == on.parsed and len(inner.calls) == 2  # and then it is a hit

    def test_a_replayed_fallback_is_still_a_fallback(self, tmp_path):
        inner = ReportingLLM([TRIAGE_V3_TRUE_POSITIVE], reports=["json_object"])
        cache = _cache(tmp_path, inner)
        cfg = _cfg(LLM_RESPONSE_FORMAT="json_schema")

        live = T.propose(cache, _build(), cfg=cfg)
        hit = T.propose(cache, _build(), cfg=cfg)

        assert live.format_fallback is True and hit.format_fallback is True
        assert len(inner.calls) == 1
