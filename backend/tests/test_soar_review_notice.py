"""SR-T1 — `app.soar.review_notice.parse`: the body n8n pushes to `POST /webhook/soar-notices` (spec 2026-11-16 §2).

Pure: bytes in, a `Notice` or every fault out. The database half (the upsert table of §2) is `test_soar_notices_webhook.py`.

The contract: `schema_version` "1.x" (another major is a 400); required `schema_version`, `event`, `kind`, `id`, `sent_at`,
`status`, and for a review `action.type` and `buttons`; every other field may be null or absent; an unknown field is ignored;
`severity` null or absent is `info`; a timestamp carries an offset; `score` is a finite number or null (stored rounded);
`processing` is the web's own and a 400 from n8n; texts are capped (`title` 200, the others 2,000 characters); and a wrong
body is a 400 listing EVERY fault as `{"field", "reason"}`.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

import pytest
from app.soar import review_notice
from app.soar.review_notice import Notice, NoticeRejected

from tests import soar_review_data as data
from tests.soar_review_data import MISSING


def _parse(doc: Any) -> Notice:
    return review_notice.parse(doc if isinstance(doc, bytes) else json.dumps(doc).encode("utf-8"))


def _faults(doc: Any) -> list[dict[str, str]]:
    with pytest.raises(NoticeRejected) as caught:
        _parse(doc)
    return caught.value.faults


def _fault(field: str, reason: str) -> dict[str, str]:
    return {"field": field, "reason": reason}


# ── a good body ─────────────────────────────────────────────────────────────────────────────


def test_the_spec_example_parses_to_the_columns_of_the_table():
    doc = data.review(id="K7QM2XHP")
    notice = _parse(doc)
    assert (notice.id, notice.event, notice.kind, notice.status) == (
        "K7QM2XHP",
        "created",
        "review",
        "open",
    )
    assert notice.sent_at == datetime(2026, 11, 13, 14, 40, 5, 123000, tzinfo=UTC)
    assert notice.sent_at.utcoffset().total_seconds() == 0
    assert notice.columns == {
        "kind": "review",
        "status": "open",
        "severity": "info",
        "title": "ĐÃ TỰ XỬ LÝ",
        "simulated": False,
        "case_id": "~4096",
        "case_number": 65,
        "action_type": "block_ip",
        "action_text": "Chặn IP 79.79.78.202 trên pfSense",
        "action_target": "79.79.78.202",
        "action_via": "pfsense",
        "action_agent": None,
        "host": "pfSense.home.arpa",
        "agent_id": "003",
        "user_name": None,
        "src_ip": "79.79.78.202",
        "domain": None,
        "scenario_id": "SC03",
        "scenario_name": "Quét cổng từ bên ngoài",
        "score": 50,
        "note": "Đã chặn 79.79.78.202 trên pfSense, tự gỡ 22:40",
        "buttons": [
            {"decision": "keep", "label": "✅ Giữ chặn"},
            {"decision": "undo", "label": "↩️ Gỡ chặn IP"},
        ],
        "created_at": datetime(2026, 11, 13, 14, 40, 3, 123000, tzinfo=UTC),
        "auto_expire_at": datetime(2026, 11, 13, 15, 40, 5, 123000, tzinfo=UTC),
        "remind_every_minutes": 0,
        "next_remind_at": None,
        "decided_by": None,
        "decided_at": None,
        "result": None,
    }


def test_the_body_is_kept_as_sent_for_raw():
    doc = data.review(extra={"deep": [1, {"x": None}]}, unknown_field="giữ nguyên")
    assert _parse(doc).raw == doc


def test_the_kill_process_review_and_the_notice_parse():
    killed = _parse(data.kill_process())
    assert killed.columns["action_type"] == "kill_process"
    assert [b["decision"] for b in killed.columns["buttons"]] == ["keep", "fp"]
    info = _parse(data.notice())
    assert (info.kind, info.status, info.columns["severity"]) == ("notice", "info", "warning")
    assert info.columns["buttons"] == []
    assert info.columns["action_type"] is None and info.columns["case_number"] is None


@pytest.mark.parametrize("event", ["created", "updated", "reminder"])
def test_the_three_events_are_accepted(event):
    assert _parse(data.review(event=event)).event == event


@pytest.mark.parametrize("status", ["open", "kept", "undone", "false_positive", "expired"])
def test_the_five_review_statuses_are_accepted(status):
    assert _parse(data.review(status=status)).status == status


def test_an_unknown_field_is_ignored_at_every_level():
    doc = data.review(brand_new="x")
    doc["action"]["extra"] = {"a": 1}
    doc["case"]["extra"] = [1]
    doc["scenario"]["extra"] = None
    doc["buttons"][0]["extra"] = "x"
    notice = _parse(doc)
    assert "brand_new" not in notice.columns
    assert notice.columns["buttons"][0] == {"decision": "keep", "label": "✅ Giữ chặn"}


def test_a_field_that_is_absent_is_the_same_as_one_that_is_null():
    optional = [
        "severity", "title", "simulated", "case", "host", "agent_id", "user", "src_ip", "domain",
        "scenario", "score", "note", "created_at", "auto_expire_at", "remind_every_minutes",
        "next_remind_at", "decided_by", "decided_at", "result",
    ]  # fmt: skip
    base = data.review(id="K7QM2XHP")
    absent = _parse(data.review(id="K7QM2XHP", **dict.fromkeys(optional, MISSING)))
    null = _parse(data.review(id="K7QM2XHP", **dict.fromkeys(optional)))
    assert absent.columns == null.columns
    assert absent.columns["severity"] == "info"
    assert absent.columns["simulated"] is False
    assert absent.columns["remind_every_minutes"] == 0
    assert (
        absent.columns["created_at"] is None
    )  # the first `sent_at` stands in, where the row is made
    assert _parse(base).columns != absent.columns


def test_the_action_and_scenario_and_case_blocks_may_each_be_empty_objects_for_a_notice():
    notice = _parse(data.notice(case={}, scenario={}, action={}))
    assert notice.columns["case_number"] is None and notice.columns["scenario_id"] is None
    assert notice.columns["action_type"] is None


def test_a_case_number_of_null_is_kept_as_none_the_soar_score_was_under_40():
    assert _parse(data.review(case={"id": None, "number": None})).columns["case_number"] is None


# ── the body is not a JSON object ───────────────────────────────────────────────────────────

BODY_FAULT = [_fault("body", "invalid")]


@pytest.mark.parametrize(
    "body",
    [
        b"",
        b"not json",
        b"{",
        b'{"a": 1,}',
        b"[]",
        b'"a"',
        b"null",
        b"42",
        b"\xff\xfe\x00",
        b"\xef\xbb\xbf{}",
        b'{"schema_version": NaN}',
        b'{"score": Infinity}',
        b'{"score": -Infinity}',
    ],
)
def test_a_body_that_is_not_one_json_object_is_one_body_fault(body):
    assert _faults(body) == BODY_FAULT


def test_a_float_too_large_to_store_is_a_body_fault_wherever_it_sits():
    """`1e999` parses to infinity, which a `jsonb` column cannot hold."""
    doc = data.review()
    body = json.dumps(doc).replace('"score": 50', '"score": 50, "unknown": 1e999').encode()
    assert _faults(body) == BODY_FAULT


@pytest.mark.parametrize("where", ["value", "key", "unknown_field_value", "nested"])
def test_a_nul_character_anywhere_in_the_body_is_a_body_fault(where):
    """`jsonb` refuses `\\u0000`: stored, it would be a 500."""
    doc = data.review()
    if where == "value":
        doc["title"] = "a\x00b"
    elif where == "key":
        doc["a\x00b"] = 1
    elif where == "unknown_field_value":
        doc["unknown"] = "x\x00"
    else:
        doc["unknown"] = {"deep": [{"k": ["\x00"]}]}
    assert _faults(doc) == BODY_FAULT


def test_a_body_nested_deeper_than_32_levels_is_a_body_fault():
    """A stored body is served as `raw`; the serialiser gives up (a 500) a little under 250 levels."""
    deep: Any = "end"
    for _ in range(40):
        deep = {"d": deep}
    assert _faults(data.review(unknown=deep)) == [_fault("body", "too_deep")]


def test_a_body_nested_to_exactly_the_limit_is_accepted_and_one_level_more_is_not():
    """The body object is level 1; `unknown` holds the rest."""
    deep: Any = "end"
    for _ in range(review_notice.MAX_DEPTH - 1):
        deep = {"d": deep}
    _parse(data.review(unknown=deep))
    assert _faults(data.review(unknown={"d": deep})) == [_fault("body", "too_deep")]


def test_a_body_nested_a_thousand_levels_is_a_fault_not_a_recursion_error():
    body = b'{"unknown": ' + b"[" * 1000 + b"]" * 1000 + b"}"
    assert _faults(body)[0]["field"] == "body"


# ── schema_version ──────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("version", ["1.0", "1.1", "1.7", "1.25"])
def test_any_1_x_version_is_accepted(version):
    _parse(data.review(schema_version=version))


@pytest.mark.parametrize("version", ["2.0", "0.9", "10.0", "3.1"])
def test_another_major_is_unsupported(version):
    assert _faults(data.review(schema_version=version)) == [
        _fault("schema_version", "unsupported_version")
    ]


@pytest.mark.parametrize("version", ["1", "1.", "1.x", "v1.0", "1.0.0", " 1.0", "one", ""])
def test_a_version_that_is_not_major_dot_minor_is_invalid(version):
    assert _faults(data.review(schema_version=version)) == [
        _fault("schema_version", "invalid_value")
    ]


@pytest.mark.parametrize("version", [1, 1.0, True, ["1.0"], {"v": "1.0"}])
def test_a_version_that_is_not_text_is_invalid_type(version):
    assert _faults(data.review(schema_version=version)) == [
        _fault("schema_version", "invalid_type")
    ]


def test_a_missing_or_null_version_is_required():
    assert _faults(data.review(schema_version=MISSING)) == [_fault("schema_version", "required")]
    assert _faults(data.review(schema_version=None)) == [_fault("schema_version", "required")]


# ── the six required fields ─────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("field", ["schema_version", "event", "kind", "id", "sent_at", "status"])
@pytest.mark.parametrize("how", [MISSING, None])
def test_a_missing_or_null_required_field_is_required(field, how):
    assert _faults(data.review(**{field: how})) == [_fault(field, "required")]


@pytest.mark.parametrize("field", ["event", "kind", "id", "sent_at", "status"])
@pytest.mark.parametrize("value", [1, True, ["x"], {"a": 1}])
def test_a_required_field_that_is_not_text_is_invalid_type(field, value):
    assert _faults(data.review(**{field: value})) == [_fault(field, "invalid_type")]


@pytest.mark.parametrize("event", ["deleted", "Created", "", "create"])
def test_an_unknown_event_is_invalid_value(event):
    assert _faults(data.review(event=event)) == [_fault("event", "invalid_value")]


@pytest.mark.parametrize("kind", ["ticket", "Review", "", "reviews"])
def test_an_unknown_kind_is_invalid_value(kind):
    assert _faults(data.review(kind=kind)) == [_fault("kind", "invalid_value")]


@pytest.mark.parametrize("status", ["closed", "Open", "", "done", "decided"])
def test_an_unknown_status_is_invalid_value(status):
    assert _faults(data.review(status=status)) == [_fault("status", "invalid_value")]


def test_processing_is_the_webs_own_and_n8n_sending_it_is_reserved():
    assert _faults(data.review(status="processing")) == [_fault("status", "reserved")]


def test_a_review_is_never_info_and_a_notice_is_always_info():
    assert _faults(data.review(status="info")) == [_fault("status", "invalid_value")]
    for status in ("open", "kept", "undone", "false_positive", "expired"):
        assert _faults(data.notice(status=status)) == [_fault("status", "invalid_value")]


# ── the id: 8 characters for a review, N + 12 for a notice ─────────────────────────────────


@pytest.mark.parametrize("id_", ["K7QM2XHP", "AAAAAAAA", "22222222", "ZZZZZZZZ", "HJKLMNPQ"])
def test_a_review_id_is_8_characters_of_the_contract_alphabet(id_):
    assert _parse(data.review(id=id_)).id == id_


@pytest.mark.parametrize(
    "id_",
    ["K7QM2XH", "K7QM2XHPP", "k7qm2xhp", "K7QM2XHO", "K7QM2XHI", "K7QM2XH0", "K7QM2XH1",
     "K7QM 2XH", "K7QM-2XH", "K7QM2XH\n", "", "ÁÁÁÁÁÁÁÁ"],
)  # fmt: skip
def test_a_review_id_outside_the_alphabet_or_the_length_is_invalid(id_):
    faults = _faults(data.review(id=id_))
    assert _fault("id", "invalid_value") in faults


@pytest.mark.parametrize(
    "id_", ["Nabcdef123456", "NABCDEF123456", "N_-_-_-_-_-_-", "N000000000000"]
)
def test_a_notice_id_is_n_and_12_letters_digits_underscores_or_dashes(id_):
    assert _parse(data.notice(id=id_)).id == id_


@pytest.mark.parametrize(
    "id_", ["nabcdef123456", "Nabcdef12345", "Nabcdef1234567", "N abcdef12345", "N.abcdef1234", "K7QM2XHP", "Nábcdef12345"]
)  # fmt: skip
def test_a_notice_id_of_another_shape_is_invalid(id_):
    assert _fault("id", "invalid_value") in _faults(data.notice(id=id_))


def test_a_review_id_given_to_a_notice_and_a_notice_id_given_to_a_review_are_both_invalid():
    assert _fault("id", "invalid_value") in _faults(data.notice(id="K7QM2XHP"))
    assert _fault("id", "invalid_value") in _faults(data.review(id="Nabcdef123456"))


# ── timestamps carry an offset ──────────────────────────────────────────────────────────────

TIMESTAMP_FIELDS = ["sent_at", "created_at", "auto_expire_at", "next_remind_at", "decided_at"]


@pytest.mark.parametrize("field", TIMESTAMP_FIELDS)
@pytest.mark.parametrize(
    "text,utc",
    [
        ("2026-11-13T21:40:05.123+07:00", datetime(2026, 11, 13, 14, 40, 5, 123000, tzinfo=UTC)),
        ("2026-11-13T14:40:05Z", datetime(2026, 11, 13, 14, 40, 5, tzinfo=UTC)),
        ("2026-11-13T14:40:05+00:00", datetime(2026, 11, 13, 14, 40, 5, tzinfo=UTC)),
        ("2026-11-13T02:40:05.5-12:00", datetime(2026, 11, 13, 14, 40, 5, 500000, tzinfo=UTC)),
        ("2026-11-13T21:40:05+0700", datetime(2026, 11, 13, 14, 40, 5, tzinfo=UTC)),
    ],
)
def test_a_timestamp_with_an_offset_is_read_and_kept_in_utc(field, text, utc):
    notice = _parse(data.review(**{field: text}))
    got = notice.sent_at if field == "sent_at" else notice.columns[field]
    assert got == utc and got.utcoffset().total_seconds() == 0


@pytest.mark.parametrize("field", TIMESTAMP_FIELDS)
@pytest.mark.parametrize(
    "text", ["2026-11-13T21:40:05", "2026-11-13 21:40:05", "2026-11-13", "2026-11-13T21:40"]
)
def test_a_timestamp_without_an_offset_is_refused(field, text):
    assert _faults(data.review(**{field: text})) == [_fault(field, "no_offset")]


@pytest.mark.parametrize("field", TIMESTAMP_FIELDS)
@pytest.mark.parametrize(
    "text",
    [
        "yesterday",
        "13/11/2026 21:40+07:00",
        "2026-13-40T00:00:00Z",
        "",
        "T",
        "2026-11-13T25:00:00Z",
    ],
)
def test_a_timestamp_that_is_not_a_time_is_invalid_value(field, text):
    assert _faults(data.review(**{field: text})) == [_fault(field, "invalid_value")]


@pytest.mark.parametrize("field", TIMESTAMP_FIELDS)
@pytest.mark.parametrize("value", [1_700_000_000, 1.5, True, ["2026-11-13T00:00:00Z"]])
def test_a_timestamp_that_is_not_text_is_invalid_type(field, value):
    assert _faults(data.review(**{field: value})) == [_fault(field, "invalid_type")]


@pytest.mark.parametrize(
    "text",
    [
        "1999-12-31T23:59:59Z",
        "2100-01-01T00:00:00Z",
        "0001-01-01T00:00:00+14:00",
        "9999-12-31T23:59:59-14:00",
    ],
)
def test_a_time_outside_the_years_2000_to_2099_in_utc_is_invalid_value(text):
    assert _faults(data.review(sent_at=text)) == [_fault("sent_at", "invalid_value")]


# ── severity, simulated, remind_every_minutes ───────────────────────────────────────────────


@pytest.mark.parametrize("severity", ["info", "warning", "error"])
def test_the_three_severities_are_kept(severity):
    assert _parse(data.review(severity=severity)).columns["severity"] == severity


@pytest.mark.parametrize("severity", [None, MISSING])
def test_a_null_or_absent_severity_is_info(severity):
    assert _parse(data.review(severity=severity)).columns["severity"] == "info"


@pytest.mark.parametrize("severity", ["critical", "Info", "", "warn"])
def test_an_unknown_severity_is_invalid_value(severity):
    assert _faults(data.review(severity=severity)) == [_fault("severity", "invalid_value")]


def test_a_severity_that_is_not_text_is_invalid_type():
    assert _faults(data.review(severity=1)) == [_fault("severity", "invalid_type")]


@pytest.mark.parametrize("value", ["true", 1, 0, "no", [], {}])
def test_simulated_must_be_a_boolean(value):
    assert _faults(data.review(simulated=value)) == [_fault("simulated", "invalid_type")]


@pytest.mark.parametrize("value,stored", [(True, True), (False, False), (None, False)])
def test_simulated_true_false_or_null(value, stored):
    assert _parse(data.review(simulated=value)).columns["simulated"] is stored


@pytest.mark.parametrize(
    "value,stored", [(0, 0), (5, 5), (1440, 1440), (None, 0), (30.0, 30), (2**31 - 1, 2**31 - 1)]
)
def test_remind_every_minutes_is_a_whole_number_of_minutes(value, stored):
    assert _parse(data.review(remind_every_minutes=value)).columns["remind_every_minutes"] == stored


@pytest.mark.parametrize("value", [-1, 2**31, 10**12, 1.5, 1e300])
def test_remind_every_minutes_outside_the_column_or_fractional_is_invalid_value(value):
    assert _faults(data.review(remind_every_minutes=value)) == [
        _fault("remind_every_minutes", "invalid_value")
    ]


@pytest.mark.parametrize("value", ["5", True, [5], {"n": 5}])
def test_remind_every_minutes_that_is_not_a_number_is_invalid_type(value):
    assert _faults(data.review(remind_every_minutes=value)) == [
        _fault("remind_every_minutes", "invalid_type")
    ]


# ── score: a finite number or null, stored rounded to an integer ────────────────────────────


@pytest.mark.parametrize(
    "value,stored",
    [
        (50, 50),
        (0, 0),
        (100, 100),
        (82.0, 82),
        (49.4, 49),
        (49.5, 50),
        (50.5, 51),
        (0.5, 1),
        (-0.4, 0),
        (-0.5, 0),
        (-1.5, -1),
        (None, None),
    ],
)
def test_a_score_is_rounded_half_up_to_an_integer(value, stored):
    assert _parse(data.review(score=value)).columns["score"] == stored


def test_a_missing_score_is_none():
    assert _parse(data.review(score=MISSING)).columns["score"] is None


@pytest.mark.parametrize("value", ["50", True, False, [50], {"v": 50}])
def test_a_score_that_is_not_a_number_is_invalid_type(value):
    assert _faults(data.review(score=value)) == [_fault("score", "invalid_type")]


@pytest.mark.parametrize("literal", ["3e9", "-3e9", "2147483648", "1e300", "-2147483649.5"])
def test_a_score_outside_the_integer_column_is_invalid_value(literal):
    body = json.dumps(data.review()).replace('"score": 50', f'"score": {literal}').encode()
    assert _faults(body) == [_fault("score", "invalid_value")]


@pytest.mark.parametrize(
    "literal,stored", [("2147483647", 2147483647), ("-2147483648", -2147483648)]
)
def test_a_score_at_the_edge_of_the_integer_column_is_kept(literal, stored):
    body = json.dumps(data.review()).replace('"score": 50', f'"score": {literal}').encode()
    assert _parse(body).columns["score"] == stored


# ── texts are capped: the title at 200, the others at 2,000 characters ──────────────────────

TEXT_FIELDS = {
    "title": 200,
    "note": 2000,
    "host": 2000,
    "agent_id": 2000,
    "user": 2000,
    "src_ip": 2000,
    "domain": 2000,
    "decided_by": 2000,
    "result": 2000,
}


@pytest.mark.parametrize("field,cap", list(TEXT_FIELDS.items()))
def test_a_text_at_its_cap_is_kept_and_one_over_is_too_long(field, cap):
    assert _parse(data.review(**{field: "é" * cap})) is not None  # characters, not bytes
    assert _faults(data.review(**{field: "é" * (cap + 1)})) == [_fault(field, "too_long")]


@pytest.mark.parametrize("field", list(TEXT_FIELDS))
@pytest.mark.parametrize("value", [1, True, ["x"], {"a": 1}])
def test_a_text_field_that_is_not_text_is_invalid_type(field, value):
    assert _faults(data.review(**{field: value})) == [_fault(field, "invalid_type")]


@pytest.mark.parametrize(
    "path,cap",
    [
        ("action.text", 2000),
        ("action.target", 2000),
        ("action.agent", 2000),
        ("case.id", 2000),
        ("scenario.id", 2000),
        ("scenario.name", 2000),
    ],
)
def test_the_nested_texts_are_capped_at_2000_characters_too(path, cap):
    assert _faults(data.edit(data.review(), path, "x" * (cap + 1))) == [_fault(path, "too_long")]
    _parse(data.edit(data.review(), path, "x" * cap))


def test_a_button_label_is_capped_at_2000_characters():
    doc = data.review()
    doc["buttons"][1]["label"] = "x" * 2001
    assert _faults(doc) == [_fault("buttons[1].label", "too_long")]


def test_a_text_is_stored_as_sent_empty_spaces_and_markup_included():
    notice = _parse(
        data.review(
            note="  <script>alert(1)</script> %s ${x} '; DROP TABLE soar_reviews;--", host=""
        )
    )
    assert (
        notice.columns["note"]
        == "  <script>alert(1)</script> %s ${x} '; DROP TABLE soar_reviews;--"
    )
    assert notice.columns["host"] == ""


# ── action ──────────────────────────────────────────────────────────────────────────────────

ACTION_TYPES = [
    "block_ip",
    "sinkhole_domain",
    "isolate_host",
    "disable_user",
    "disable_xp_cmdshell",
    "kill_process",
]


@pytest.mark.parametrize("action_type", ACTION_TYPES)
def test_the_six_action_types_are_accepted(action_type):
    assert (
        _parse(data.edit(data.review(), "action.type", action_type)).columns["action_type"]
        == action_type
    )


@pytest.mark.parametrize("action_type", ["block", "Block_IP", "", "delete_host", "kill_process "])
def test_any_other_action_type_is_invalid_value(action_type):
    assert _faults(data.edit(data.review(), "action.type", action_type)) == [
        _fault("action.type", "invalid_value")
    ]


def test_a_review_needs_its_action_type():
    assert _faults(data.edit(data.review(), "action.type")) == [_fault("action.type", "required")]
    assert _faults(data.edit(data.review(), "action.type", None)) == [
        _fault("action.type", "required")
    ]
    assert _faults(data.review(action=MISSING)) == [_fault("action.type", "required")]
    assert _faults(data.review(action=None)) == [_fault("action.type", "required")]
    assert _faults(data.review(action={})) == [_fault("action.type", "required")]


def test_a_notice_may_have_no_action_or_one_with_a_type():
    assert _parse(data.notice(action=MISSING)).columns["action_type"] is None
    assert (
        _parse(data.notice(action={"type": "block_ip", "text": "x"})).columns["action_type"]
        == "block_ip"
    )
    assert _faults(data.notice(action={"type": "nope"})) == [_fault("action.type", "invalid_value")]


@pytest.mark.parametrize("via", ["pfsense", "wazuh", None])
def test_the_two_channels_and_null_are_accepted(via):
    assert _parse(data.edit(data.review(), "action.via", via)).columns["action_via"] == via


@pytest.mark.parametrize("via", ["PFSENSE", "n8n", "", "wazuh "])
def test_any_other_channel_is_invalid_value(via):
    assert _faults(data.edit(data.review(), "action.via", via)) == [
        _fault("action.via", "invalid_value")
    ]


@pytest.mark.parametrize("block", ["action", "case", "scenario"])
@pytest.mark.parametrize("value", ["x", 1, [1], True])
def test_a_block_that_is_not_an_object_is_invalid_type(block, value):
    faults = _faults(data.review(**{block: value}))
    assert _fault(block, "invalid_type") in faults


# ── case ────────────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "number,stored", [(65, 65), (0, 0), (2**63 - 1, 2**63 - 1), (65.0, 65), (None, None)]
)
def test_a_case_number_is_a_whole_number(number, stored):
    assert _parse(data.edit(data.review(), "case.number", number)).columns["case_number"] == stored


@pytest.mark.parametrize("number", [-1, 2**63, 65.5, 10**30])
def test_a_case_number_negative_fractional_or_beyond_bigint_is_invalid_value(number):
    assert _faults(data.edit(data.review(), "case.number", number)) == [
        _fault("case.number", "invalid_value")
    ]


@pytest.mark.parametrize("number", ["65", True, [65]])
def test_a_case_number_that_is_not_a_number_is_invalid_type(number):
    assert _faults(data.edit(data.review(), "case.number", number)) == [
        _fault("case.number", "invalid_type")
    ]


@pytest.mark.parametrize(
    "path",
    ["case.id", "scenario.id", "scenario.name", "action.text", "action.target", "action.agent"],
)
def test_a_nested_text_that_is_not_text_is_invalid_type(path):
    assert _faults(data.edit(data.review(), path, 12)) == [_fault(path, "invalid_type")]


# ── buttons ─────────────────────────────────────────────────────────────────────────────────


def test_a_review_needs_its_buttons_a_list_which_may_be_empty():
    assert _faults(data.review(buttons=MISSING)) == [_fault("buttons", "required")]
    assert _faults(data.review(buttons=None)) == [_fault("buttons", "required")]
    assert _parse(data.review(buttons=[])).columns["buttons"] == []


@pytest.mark.parametrize("value", ["keep", 1, {"decision": "keep", "label": "x"}, True])
def test_buttons_that_are_not_a_list_are_invalid_type(value):
    assert _faults(data.review(buttons=value)) == [_fault("buttons", "invalid_type")]


@pytest.mark.parametrize("item", ["keep", 1, None, ["keep"]])
def test_a_button_that_is_not_an_object_is_invalid_type(item):
    assert _faults(data.review(buttons=[{"decision": "keep", "label": "x"}, item])) == [
        _fault("buttons[1]", "invalid_type")
    ]


@pytest.mark.parametrize("decision", ["keep", "undo", "fp"])
def test_the_three_decisions_are_accepted(decision):
    assert (
        _parse(data.review(buttons=[{"decision": decision, "label": "x"}])).columns["buttons"][0][
            "decision"
        ]
        == decision
    )


@pytest.mark.parametrize("decision", ["delete", "Keep", "", "false_positive", "kept"])
def test_any_other_decision_is_invalid_value(decision):
    assert _faults(data.review(buttons=[{"decision": decision, "label": "x"}])) == [
        _fault("buttons[0].decision", "invalid_value")
    ]


def test_a_button_needs_a_decision_and_a_text_label():
    assert _faults(data.review(buttons=[{"label": "x"}])) == [
        _fault("buttons[0].decision", "required")
    ]
    assert _faults(data.review(buttons=[{"decision": "keep"}])) == [
        _fault("buttons[0].label", "required")
    ]
    assert _faults(data.review(buttons=[{"decision": "keep", "label": 5}])) == [
        _fault("buttons[0].label", "invalid_type")
    ]
    assert _faults(data.review(buttons=[{"decision": 5, "label": "x"}])) == [
        _fault("buttons[0].decision", "invalid_type")
    ]


def test_a_notice_may_leave_its_buttons_out():
    assert _parse(data.notice(buttons=MISSING)).columns["buttons"] == []
    assert _parse(data.notice(buttons=None)).columns["buttons"] == []


def test_at_most_20_buttons():
    many = [{"decision": "keep", "label": str(i)} for i in range(21)]
    assert _faults(data.review(buttons=many)) == [_fault("buttons", "invalid_value")]
    assert len(_parse(data.review(buttons=many[:20])).columns["buttons"]) == 20


# ── every fault, listed ─────────────────────────────────────────────────────────────────────


def test_a_body_with_many_faults_lists_every_one_in_field_order():
    doc = data.review(
        schema_version="2.0",
        event="deleted",
        id="short",
        sent_at="2026-11-13T21:40:05",
        status="processing",
        severity="bad",
        title="t" * 201,
        simulated="yes",
        score="x",
        created_at="yesterday",
        remind_every_minutes=-3,
        buttons=[{"decision": "nope", "label": 1}],
    )
    doc["action"]["type"] = "nope"
    doc["case"]["number"] = -1
    assert _faults(doc) == [
        _fault("schema_version", "unsupported_version"),
        _fault("event", "invalid_value"),
        _fault("id", "invalid_value"),
        _fault("sent_at", "no_offset"),
        _fault("status", "reserved"),
        _fault("severity", "invalid_value"),
        _fault("title", "too_long"),
        _fault("simulated", "invalid_type"),
        _fault("case.number", "invalid_value"),
        _fault("action.type", "invalid_value"),
        _fault("score", "invalid_type"),
        _fault("created_at", "invalid_value"),
        _fault("remind_every_minutes", "invalid_value"),
        _fault("buttons[0].decision", "invalid_value"),
        _fault("buttons[0].label", "invalid_type"),
    ]


def test_a_body_with_all_six_required_fields_missing_lists_all_six_and_the_review_ones():
    faults = _faults({"title": "x"})
    assert [f["field"] for f in faults] == [
        "schema_version", "event", "kind", "id", "sent_at", "status",
    ]  # fmt: skip
    assert {f["reason"] for f in faults} == {"required"}


def test_a_review_with_nothing_but_the_required_six_lists_the_two_a_review_adds():
    doc = {
        "schema_version": "1.0",
        "event": "created",
        "kind": "review",
        "id": "K7QM2XHP",
        "sent_at": "2026-11-13T21:40:05+07:00",
        "status": "open",
    }
    assert _faults(doc) == [_fault("action.type", "required"), _fault("buttons", "required")]


def test_a_fault_names_the_field_never_the_value():
    for fault in _faults(data.review(severity="<img src=x onerror=alert(1)>", title="t" * 300)):
        assert set(fault) == {"field", "reason"}
        assert "<" not in json.dumps(fault) and "ttt" not in json.dumps(fault)


def test_an_unknown_kind_does_not_hide_the_other_faults_but_skips_the_checks_that_need_it():
    faults = _faults(data.review(kind="ticket", severity="bad"))
    assert faults == [_fault("kind", "invalid_value"), _fault("severity", "invalid_value")]
