"""`llm.triage._call` / `propose` / `verify` and `LLM_RESPONSE_FORMAT` (DEC-218, spec sections 5 and 6). PURE.

With the switch on, the proposer's and the verifier's first call and repair call each pass
`response_format={"type": "json_schema", "json_schema": {"name", "strict": true, "schema"}}` with the schema
they are validated against; with it off (the default) nothing is passed and the request is exactly what it
was. The prompts do not move: the system prompt, the user message and `prompt_version` are the same bytes
with the switch on and off. `Proposal.first_errors` is the first call's validator messages; they are for the
database only (spec 6), and the repair prompt still shows the model the sanitised bullets it always did.
"""

from __future__ import annotations

import copy
import json
from types import SimpleNamespace

import pytest
from app.llm import schemas
from app.llm import triage as T
from app.llm.adapter import DeepSeekAdapter, LLMResult

from tests.fakes.llm import TRIAGE_V3_TRUE_POSITIVE, VERIFIER_V2_AGREE
from tests.test_llm_triage import _build, _cfg, _lint, _verifier

ON = "json_schema"
OFF = "json_object"

TRIAGE_BAD = {"suggested_action": "maybe"}  # fails the schema: the repair round follows
VERIFIER_BAD = {"agree": "yes"}


def _format(name: str) -> dict:
    return {
        "type": "json_schema",
        "json_schema": {"name": name, "strict": True, "schema": schemas.json_schema(name)},
    }


class _Spy:
    """An adapter double that keeps exactly the keyword arguments `complete` was called with, so "not passed"
    and "passed as None" are different things, and answers from a queue. `reported` is what each result
    says about the format that produced it (`LLMResult.response_format`)."""

    def __init__(self, contents, *, reported=None):
        self.kwargs: list[dict] = []
        self._contents = list(contents)
        self._reported = list(reported) if isinstance(reported, list) else None
        self._reported_one = reported if not isinstance(reported, list) else None

    def complete(self, **kwargs):
        self.kwargs.append(kwargs)
        content = self._contents.pop(0)
        content = content if isinstance(content, str) else json.dumps(content)
        index = len(self.kwargs) - 1
        reported = self._reported[index] if self._reported is not None else self._reported_one
        return LLMResult(
            content=content,
            model="m",
            usage={"prompt_tokens": 3, "completion_tokens": 2},
            latency_ms=1,
            response_format=reported,
        )


# (the function, the schema name, a valid answer, a bad one, how to build its prompt)
ROLES = [
    pytest.param(
        T.propose, "triage_v3", TRIAGE_V3_TRUE_POSITIVE, TRIAGE_BAD, _build, id="proposer"
    ),
    pytest.param(
        T.verify, "verifier_v2", VERIFIER_V2_AGREE, VERIFIER_BAD, _verifier, id="verifier"
    ),
]


class TestTheFormatIsPassedWhenTheSwitchIsOn:
    @pytest.mark.parametrize("call,name,good,bad,build", ROLES)
    def test_the_first_call_carries_the_format_with_the_schema_name(
        self, call, name, good, bad, build
    ):
        spy = _Spy([good])

        call(spy, build(), cfg=_cfg(LLM_RESPONSE_FORMAT=ON))

        assert len(spy.kwargs) == 1
        assert spy.kwargs[0]["response_format"] == _format(name)

    @pytest.mark.parametrize("call,name,good,bad,build", ROLES)
    def test_the_repair_call_carries_the_same_format(self, call, name, good, bad, build):
        spy = _Spy([bad, good])

        result = call(spy, build(), cfg=_cfg(LLM_RESPONSE_FORMAT=ON))

        assert result.repaired is True and len(spy.kwargs) == 2
        assert spy.kwargs[0]["response_format"] == spy.kwargs[1]["response_format"] == _format(name)

    @pytest.mark.parametrize("call,name,good,bad,build", ROLES)
    def test_the_schema_is_the_generated_one_and_the_name_is_the_one_validated_against(
        self, call, name, good, bad, build
    ):
        spy = _Spy([good])

        call(spy, build(), cfg=_cfg(LLM_RESPONSE_FORMAT=ON))

        sent = spy.kwargs[0]["response_format"]["json_schema"]
        assert sent["name"] == name and sent["strict"] is True
        assert sent["schema"] == schemas.json_schema(name)
        # what the validator accepts is what the provider is asked for: the answer the product's own
        # double gives is a member of the schema's key set
        assert set(sent["schema"]["required"]) == set(good)

    def test_the_proposer_and_the_verifier_name_different_schemas(self):
        proposer, verifier = _Spy([TRIAGE_V3_TRUE_POSITIVE]), _Spy([VERIFIER_V2_AGREE])
        cfg = _cfg(LLM_RESPONSE_FORMAT=ON)

        T.propose(proposer, _build(), cfg=cfg)
        T.verify(verifier, _verifier(), cfg=cfg)

        assert proposer.kwargs[0]["response_format"]["json_schema"]["name"] == "triage_v3"
        assert verifier.kwargs[0]["response_format"]["json_schema"]["name"] == "verifier_v2"

    @pytest.mark.parametrize("call,name,good,bad,build", ROLES)
    def test_the_model_and_the_messages_are_still_passed(self, call, name, good, bad, build):
        spy = _Spy([good])
        built = build()

        call(spy, built, cfg=_cfg(LLM_RESPONSE_FORMAT=ON))

        kwargs = spy.kwargs[0]
        assert set(kwargs) == {"system", "user", "model", "response_format"}
        assert kwargs["system"] == built.prompt.system and kwargs["user"] == built.prompt.user


class TestNothingIsPassedWhenTheSwitchIsOff:
    @pytest.mark.parametrize("flag", [OFF, None], ids=["json_object", "default"])
    @pytest.mark.parametrize("call,name,good,bad,build", ROLES)
    def test_response_format_is_not_in_the_call_at_all(self, call, name, good, bad, build, flag):
        spy = _Spy([bad, good])
        cfg = _cfg() if flag is None else _cfg(LLM_RESPONSE_FORMAT=flag)

        result = call(spy, build(), cfg=cfg)

        assert result.repaired is True and len(spy.kwargs) == 2
        for kwargs in spy.kwargs:
            assert "response_format" not in kwargs
            assert set(kwargs) == {"system", "user", "model"}

    @pytest.mark.parametrize("call,name,good,bad,build", ROLES)
    def test_through_the_real_adapter_the_provider_request_is_exactly_todays(
        self, call, name, good, bad, build
    ):
        """The whole request, key for key: nothing new, nothing missing, the same `json_object`."""
        client = _FakeClient([bad, good])
        cfg = _cfg(LLM_API_KEY="k", LLM_BASE_URL="http://127.0.0.1:9", LLM_TIMEOUT_S=5)
        built = build()

        call(DeepSeekAdapter(cfg, client=client), built, cfg=cfg)

        repair_user = client.calls[1]["user_sent"]
        assert repair_user.startswith(built.prompt.user)
        for kwargs in client.calls:
            expected_model = "proposer-model" if name == "triage_v3" else "verifier-model"
            assert {k: v for k, v in kwargs.items() if k != "user_sent"} == {
                "model": expected_model,
                "messages": [
                    {"role": "system", "content": built.prompt.system},
                    {"role": "user", "content": kwargs["user_sent"]},
                ],
                "response_format": {"type": "json_object"},
                "extra_body": {"thinking": {"type": "disabled"}},
                "timeout": 5,
            }

    @pytest.mark.parametrize("call,name,good,bad,build", ROLES)
    def test_through_the_real_adapter_with_the_switch_on_only_the_format_differs(
        self, call, name, good, bad, build
    ):
        client = _FakeClient([bad, good])
        cfg = _cfg(
            LLM_API_KEY="k",
            LLM_BASE_URL="http://127.0.0.1:9",
            LLM_TIMEOUT_S=5,
            LLM_RESPONSE_FORMAT=ON,
        )

        call(DeepSeekAdapter(cfg, client=client), build(), cfg=cfg)

        for kwargs in client.calls:
            assert kwargs["response_format"] == _format(name)
            assert kwargs["extra_body"] == {"thinking": {"type": "disabled"}}
            assert kwargs["timeout"] == 5


class _FakeClient:
    """`client.chat.completions.create(**kwargs)` for the real `DeepSeekAdapter`; keeps the user message it
    was sent next to the keyword arguments."""

    def __init__(self, contents):
        self.calls: list[dict] = []
        self._contents = [c if isinstance(c, str) else json.dumps(c) for c in contents]
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, **kwargs):
        self.calls.append({**kwargs, "user_sent": kwargs["messages"][1]["content"]})
        message = SimpleNamespace(content=self._contents.pop(0), model_extra={})
        return SimpleNamespace(
            choices=[SimpleNamespace(message=message)],
            model="deepseek-fake",
            usage={"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
        )


class TestThePromptsDoNotMove:
    """The switch changes what the provider is asked to enforce, never what the model is told."""

    @pytest.mark.parametrize("call,name,good,bad,build", ROLES)
    def test_the_system_prompt_and_the_user_message_are_byte_identical_on_and_off(
        self, call, name, good, bad, build
    ):
        off, on = _Spy([bad, good]), _Spy([bad, good])
        built_off = build(cfg=_cfg(LLM_RESPONSE_FORMAT=OFF)) if build is _build else build()
        built_on = build(cfg=_cfg(LLM_RESPONSE_FORMAT=ON)) if build is _build else build()

        call(off, built_off, cfg=_cfg(LLM_RESPONSE_FORMAT=OFF))
        call(on, built_on, cfg=_cfg(LLM_RESPONSE_FORMAT=ON))

        assert built_on.prompt.system.encode() == built_off.prompt.system.encode()
        assert built_on.prompt.user.encode() == built_off.prompt.user.encode()
        assert len(off.kwargs) == len(on.kwargs) == 2
        for sent_off, sent_on in zip(off.kwargs, on.kwargs, strict=True):
            assert sent_on["system"].encode() == sent_off["system"].encode()  # the repair call too
            assert sent_on["user"].encode() == sent_off["user"].encode()

    def test_the_system_prompts_do_not_mention_the_format(self):
        for built in (_build(cfg=_cfg(LLM_RESPONSE_FORMAT=ON)), _verifier()):
            assert "json_schema" not in built.prompt.system
            assert "strict" not in built.prompt.system

    @pytest.mark.parametrize("template", [T.TRIAGE_TEMPLATE, T.VERIFIER_TEMPLATE])
    def test_prompt_version_is_the_same_with_the_switch_on_and_off(self, template, monkeypatch):
        """`prompt_version(template)` is a function of the template file's bytes and the git revision: it
        reads no configuration, and the module's per-process cache is cleared so each value is computed.
        """
        values = []
        for flag in (OFF, ON):
            monkeypatch.setenv("LLM_RESPONSE_FORMAT", flag)
            monkeypatch.setattr(T, "_PROMPT_VERSION_CACHE", {})
            values.append(T.prompt_version(template))
        assert values[0] == values[1]

    def test_propose_does_not_touch_the_prompt_version_cache(self, monkeypatch):
        monkeypatch.setattr(T, "_PROMPT_VERSION_CACHE", {})
        T.propose(_Spy([TRIAGE_V3_TRUE_POSITIVE]), _build(), cfg=_cfg(LLM_RESPONSE_FORMAT=ON))
        T.verify(_Spy([VERIFIER_V2_AGREE]), _verifier(), cfg=_cfg(LLM_RESPONSE_FORMAT=ON))
        assert T._PROMPT_VERSION_CACHE == {}


class TestFirstErrors:
    """`Proposal.first_errors`: the first call's validator messages, `[]` when it was valid (spec 5, 6)."""

    @pytest.mark.parametrize("call,name,good,bad,build", ROLES)
    def test_a_valid_first_call_has_none(self, call, name, good, bad, build):
        result = call(_Spy([good]), build(), cfg=_cfg())

        assert result.first_errors == [] and result.schema_errors == []
        assert result.repaired is False

    @pytest.mark.parametrize("call,name,good,bad,build", ROLES)
    def test_a_repaired_run_keeps_what_the_first_call_got_wrong(self, call, name, good, bad, build):
        result = call(_Spy([bad, good]), build(), cfg=_cfg())

        assert result.repaired is True and result.schema_errors == []
        assert result.first_errors == schemas.validate(name, schemas.normalise(name, bad))
        assert result.first_errors  # not empty: that is why there was a repair call

    @pytest.mark.parametrize("call,name,good,bad,build", ROLES)
    def test_a_run_that_fails_for_good_keeps_both_the_first_and_the_last(
        self, call, name, good, bad, build
    ):
        other = {"unexpected_thing": 1}
        result = call(_Spy([bad, other]), build(), cfg=_cfg())

        assert result.parsed is None
        assert result.first_errors == schemas.validate(name, bad)
        assert result.schema_errors == schemas.validate(name, other)
        assert result.first_errors != result.schema_errors

    def test_the_two_lists_are_separate_objects(self):
        result = T.propose(_Spy([TRIAGE_BAD, TRIAGE_BAD]), _build(), cfg=_cfg())

        assert result.first_errors == result.schema_errors
        assert result.first_errors is not result.schema_errors

    def test_a_json_that_does_not_parse_is_a_root_error_in_first_errors(self):
        result = T.propose(_Spy(["not json at all", TRIAGE_V3_TRUE_POSITIVE]), _build(), cfg=_cfg())

        assert result.first_errors == ["<root>: expected a JSON object"]
        assert result.schema_errors == []

    def test_the_misspelt_key_is_in_first_errors_by_name_and_not_in_the_repair_prompt(self):
        """The 8 % case (spec 1): `reasones` for `reasons`. The stored message names the key; the repair
        prompt, which goes to the model, never does (planning decision 9)."""
        wrong = copy.deepcopy(TRIAGE_V3_TRUE_POSITIVE)
        wrong["reasones"] = wrong.pop("reasons")
        spy = _Spy([wrong, TRIAGE_V3_TRUE_POSITIVE])

        result = T.propose(spy, _build(), cfg=_cfg())

        assert "reasones: unexpected key" in result.first_errors
        assert "reasons: missing" in result.first_errors
        repair_user = spy.kwargs[1]["user"]
        assert "reasones" not in repair_user
        assert "- <root>: unexpected key" in repair_user
        assert _lint(repair_user, extra=T.REPAIR_CONSTANTS) == []

    def test_no_stored_message_is_in_any_prompt_sent_when_the_switch_is_on(self):
        wrong = copy.deepcopy(TRIAGE_V3_TRUE_POSITIVE)
        wrong["IGNORE_PREVIOUS_INSTRUCTIONS"] = 1
        spy = _Spy([wrong, wrong])

        result = T.propose(spy, _build(), cfg=_cfg(LLM_RESPONSE_FORMAT=ON))

        stored = result.first_errors + result.schema_errors
        assert any("IGNORE_PREVIOUS_INSTRUCTIONS" in message for message in stored)
        for kwargs in spy.kwargs:
            assert "IGNORE_PREVIOUS_INSTRUCTIONS" not in kwargs["user"]
            assert "IGNORE_PREVIOUS_INSTRUCTIONS" not in kwargs["system"]
            assert "IGNORE_PREVIOUS_INSTRUCTIONS" not in json.dumps(kwargs["response_format"])


class TestFormatFallbackIsNoticed:
    """`Proposal.format_fallback`: a call that asked for `json_schema` and was answered as `json_object`."""

    @pytest.mark.parametrize("call,name,good,bad,build", ROLES)
    def test_a_result_that_says_json_object_to_a_schema_request_is_a_fallback(
        self, call, name, good, bad, build
    ):
        result = call(
            _Spy([good], reported="json_object"), build(), cfg=_cfg(LLM_RESPONSE_FORMAT=ON)
        )

        assert result.format_fallback is True
        assert result.parsed == good  # the run goes on with what the provider gave

    @pytest.mark.parametrize("call,name,good,bad,build", ROLES)
    def test_a_fallback_on_the_repair_call_alone_counts(self, call, name, good, bad, build):
        spy = _Spy([bad, good], reported=["json_schema", "json_object"])

        result = call(spy, build(), cfg=_cfg(LLM_RESPONSE_FORMAT=ON))

        assert result.format_fallback is True

    @pytest.mark.parametrize("call,name,good,bad,build", ROLES)
    def test_a_fallback_on_the_first_call_alone_counts(self, call, name, good, bad, build):
        spy = _Spy([bad, good], reported=["json_object", "json_schema"])

        result = call(spy, build(), cfg=_cfg(LLM_RESPONSE_FORMAT=ON))

        assert result.format_fallback is True

    @pytest.mark.parametrize("call,name,good,bad,build", ROLES)
    def test_a_result_that_says_json_schema_is_not_a_fallback(self, call, name, good, bad, build):
        result = call(
            _Spy([bad, good], reported="json_schema"), build(), cfg=_cfg(LLM_RESPONSE_FORMAT=ON)
        )

        assert result.format_fallback is False

    @pytest.mark.parametrize("call,name,good,bad,build", ROLES)
    def test_a_result_that_says_nothing_is_not_a_fallback(self, call, name, good, bad, build):
        """A double, or a cached result (`eval/llm_cache.py`): no format is known, so none is reported."""
        result = call(_Spy([good], reported=None), build(), cfg=_cfg(LLM_RESPONSE_FORMAT=ON))

        assert result.format_fallback is False

    @pytest.mark.parametrize("call,name,good,bad,build", ROLES)
    def test_with_the_switch_off_json_object_is_what_was_asked_so_never_a_fallback(
        self, call, name, good, bad, build
    ):
        result = call(_Spy([good], reported="json_object"), build(), cfg=_cfg())

        assert result.format_fallback is False

    def test_through_the_real_adapter_a_refused_schema_request_is_noticed_end_to_end(self):
        client = _RefusingClient([TRIAGE_V3_TRUE_POSITIVE])
        cfg = _cfg(
            LLM_API_KEY="k",
            LLM_BASE_URL="http://127.0.0.1:9",
            LLM_TIMEOUT_S=5,
            LLM_RESPONSE_FORMAT=ON,
        )

        result = T.propose(DeepSeekAdapter(cfg, client=client), _build(), cfg=cfg)

        assert [c["response_format"]["type"] for c in client.calls] == [
            "json_schema",
            "json_object",
        ]
        assert result.format_fallback is True and result.calls == 1  # the model was called once
        assert result.parsed == TRIAGE_V3_TRUE_POSITIVE


class _RefusingClient(_FakeClient):
    """Refuses the first request, which asks for a JSON Schema, with a 400, as a provider that does not know
    the format would; answers the next ones."""

    def _create(self, **kwargs):
        if not self.calls and kwargs["response_format"]["type"] == "json_schema":
            self.calls.append({**kwargs, "user_sent": kwargs["messages"][1]["content"]})
            exc = Exception("HTTP 400")
            exc.status_code = 400
            raise exc
        return super()._create(**kwargs)
