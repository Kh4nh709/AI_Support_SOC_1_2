"""ingest/wazuh_parser.py — one pure parser for three Wazuh document shapes.

No DB, no clock, no network (R1, R7): every fixture here is a file already on
disk or an inline dict. Test names keep phase-1's Vietnamese "Test bắt buộc"
names (docs/phase-1-tiep-nhan-chuan-hoa.md:488-549) so acceptance 1's coverage
check can find them by name; a handful adapt the *assertion* to P2's rulings
(event_time always None — planning decision 5; no-agent never rejects —
DEC-014) and say so in their docstring, which acceptance 1 also accepts
("by name or docstring").

Exempted here (per this card's acceptance 1, owned elsewhere):
  - the three B5 `is_synthetic` tests -> P2-T12 (webhook)
  - the two "Sau Đề xuất 1" config tests -> P2-T01 (infra/config.py)
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from app.ingest.wazuh_parser import parse_wazuh_alert

FIXTURES = Path(__file__).parent / "fixtures"
PLAYBOOKS = Path(__file__).parent.parent.parent / "kb" / "playbooks"

CANONICAL_HASH = "76fcfceb90ed06f6be274be022445ff693254b73edbdb70180244328119b2a1a"


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


@pytest.fixture()
def canonical_hit() -> dict:
    return _load("alert_40112.json")


@pytest.fixture()
def canonical_expected() -> dict:
    return _load("alert_40112.expected.json")


@pytest.fixture()
def no_fields_hit() -> dict:
    return _load("indexer_hit_no_fields.json")


@pytest.fixture()
def archive_bare_doc() -> dict:
    return _load("archive_line_5503.json")


# ---------------------------------------------------------------------------
# Parse & ánh xạ — three shapes, identity, raw_payload
# ---------------------------------------------------------------------------


def test_nhan_ca_hai_dang_payload(canonical_hit, archive_bare_doc):
    """Phase-1's 'two shapes' becomes three in v3 (design note 1): indexer hit
    (has `_source`), bare Logstash/webhook document, raw archive line. All
    three parse without rejection."""
    r_hit = parse_wazuh_alert(canonical_hit)
    assert r_hit.rejection is None and r_hit.alert is not None

    r_bare = parse_wazuh_alert(archive_bare_doc)
    assert r_bare.rejection is None and r_bare.alert is not None

    raw_line = json.loads(archive_bare_doc["event"]["original"])
    r_raw = parse_wazuh_alert(raw_line)
    assert r_raw.rejection is None and r_raw.alert is not None


def test_indexer_hit_envelope_is_indexer_hit(canonical_hit):
    assert parse_wazuh_alert(canonical_hit).envelope == "indexer_hit"


def test_bare_logstash_document_envelope_is_bare(archive_bare_doc):
    assert parse_wazuh_alert(archive_bare_doc).envelope == "bare"


def test_raw_archive_line_envelope_is_bare(archive_bare_doc):
    raw_line = json.loads(archive_bare_doc["event"]["original"])
    assert parse_wazuh_alert(raw_line).envelope == "bare"


def test_alert_id_lay_source_id_khong_lay__id(canonical_hit):
    """`alert_id` comes from `_source.id`, never OpenSearch's own `_id`
    (phase-1 B5) — `_id` can change on re-index; `_source.id` is stable."""
    result = parse_wazuh_alert(canonical_hit)
    assert result.alert.alert_id == "1786903016.121311"
    assert result.alert.alert_id != canonical_hit["_id"]


def test_thieu_agent_name_van_parse_duoc(canonical_hit):
    """No `agent` object at all -> still parses (DEC-014), never rejected."""
    doc = json.loads(json.dumps(canonical_hit))
    del doc["_source"]["agent"]
    result = parse_wazuh_alert(doc)
    assert result.rejection is None
    assert result.alert.agent_name == "IA1803"  # manager.name fallback
    assert result.alert.agent_id is None
    assert result.alert.agent_ip is None


def test_khong_co_doi_tuong_agent_khong_bao_gio_bi_tu_choi(canonical_hit):
    """Same case as above, worded as the acceptance line's 'no-agent
    fallback': rejection stays None and origin_host still resolves."""
    doc = json.loads(json.dumps(canonical_hit))
    del doc["_source"]["agent"]
    result = parse_wazuh_alert(doc)
    assert result.rejection is None
    assert result.alert.origin_host == "user1-IA1803"  # predecoder.hostname wins


def test_thieu_rule_id_tra_400_neu_dung_ten_truong():
    """Rejection names the missing field, not an HTTP code (v3 rejects inside
    a pure function; the 400 is the caller's business, not the parser's) —
    but the field name is exactly 'rule.id'."""
    result = parse_wazuh_alert({"id": "1", "rule": {"description": "x"}, "timestamp": "x"})
    assert result.alert is None
    assert result.rejection == "rule.id"


def test_raw_payload_giu_nguyen_ven(canonical_hit):
    """raw_payload is the `_source` object itself, byte-for-byte the same
    structure (kể cả các trường không map: manager, input.type, location,
    rule.frequency, rule.firedtimes, rule.mail, rule.mitre.technique[])."""
    result = parse_wazuh_alert(canonical_hit)
    assert result.alert.raw_payload == canonical_hit["_source"]
    assert result.alert.raw_payload["manager"] == {"name": "IA1803"}
    assert result.alert.raw_payload["rule"]["frequency"] == 2
    assert result.alert.raw_payload["rule"]["mitre"]["technique"] == [
        "Valid Accounts",
        "Brute Force",
    ]
    # the envelope itself is NOT part of raw_payload (design note 2)
    assert "_id" not in result.alert.raw_payload
    assert "_index" not in result.alert.raw_payload


def test_raw_payload_khong_phai_tham_chieu_toi_envelope(archive_bare_doc):
    """For a bare document, raw_payload is the document itself (there is no
    envelope to strip)."""
    result = parse_wazuh_alert(archive_bare_doc)
    assert result.alert.raw_payload == archive_bare_doc


# ---------------------------------------------------------------------------
# Thời gian — offset normalisation, fields.timestamp, event_time (P2 override)
# ---------------------------------------------------------------------------


def test_timestamp_offset_khong_dau_hai_cham(archive_bare_doc):
    """'+0700' (no colon) is exactly the sample archive line's own shape.
    `datetime.fromisoformat` parses it natively on py312; `_parse_iso`
    normalises it anyway so the parser does not depend on the interpreter
    version (report §3)."""
    raw_line = json.loads(archive_bare_doc["event"]["original"])
    assert raw_line["timestamp"] == "2026-09-02T16:15:36.255+0700"
    result = parse_wazuh_alert(raw_line)
    assert result.rejection is None
    assert result.alert.alert_time == datetime(2026, 9, 2, 9, 15, 36, 255_000, tzinfo=UTC)


def test_alert_time_khop_voi_fields_timestamp(canonical_hit):
    """The payload carries its own answer: `fields.timestamp[0]` equals the
    expected `alert_time` after normalisation."""
    result = parse_wazuh_alert(canonical_hit)
    expected = canonical_hit["fields"]["timestamp"][0]
    assert result.alert.alert_time == datetime.fromisoformat(expected)


def test_event_time_suy_duoc_nam_tu_alert_time(canonical_hit):
    """P2 override (planning decision 5): F4 would infer the year from
    alert_time, but the inventory has no per-agent timezone field, so P2
    always stores event_time=None and leaves predecoder.timestamp untouched
    inside raw_payload."""
    result = parse_wazuh_alert(canonical_hit)
    assert result.alert.event_time is None
    assert result.alert.raw_payload["predecoder"]["timestamp"] == "Aug 16 17:56:55"


def test_event_time_giao_thua_tru_mot_nam():
    """P2 override: even the New Year's Eve edge case (log dated 31/12, alert
    dated 01/01) still yields event_time=None — there is no year-inference
    branch to exercise in P2 (planning decision 5)."""
    doc = {
        "_source": {
            "id": "1.1",
            "rule": {"id": "1", "description": "d"},
            "predecoder": {"timestamp": "Dec 31 23:59:59"},
            "timestamp": "2027-01-01T00:00:01+0000",
        }
    }
    result = parse_wazuh_alert(doc)
    assert result.rejection is None
    assert result.alert.event_time is None


def test_event_time_hong_thi_null_khong_raise():
    """A garbage predecoder.timestamp never raises and never blocks the
    alert — event_time is None regardless (P2 override, planning decision 5)."""
    doc = {
        "_source": {
            "id": "1.1",
            "rule": {"id": "1", "description": "d"},
            "predecoder": {"timestamp": "not-a-time"},
            "timestamp": "2026-08-16T17:56:56.130+0000",
        }
    }
    result = parse_wazuh_alert(doc)
    assert result.rejection is None
    assert result.alert.event_time is None


def test_khong_du_lieu_thoi_gian_bi_tu_choi_dung_ten_truong():
    """Neither fields.timestamp nor timestamp parses -> reject, field named
    'timestamp', never now()."""
    result = parse_wazuh_alert({"id": "1", "rule": {"id": "1", "description": "d"}})
    assert result.alert is None
    assert result.rejection == "timestamp"


# ---------------------------------------------------------------------------
# Ép kiểu — C2, B1
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad_port", ["unknown", "", "  48104  ", None])
def test_srcport_khong_phai_so_tra_0_hoac_gia_tri_sach(bad_port):
    doc = {
        "_source": {
            "id": "1.1",
            "rule": {"id": "1", "description": "d"},
            "timestamp": "2026-08-16T17:56:56.130+0000",
            "data": {"srcport": bad_port},
        }
    }
    result = parse_wazuh_alert(doc)
    assert result.rejection is None
    expected = 48104 if bad_port == "  48104  " else 0
    assert result.alert.src_port == expected


def test_dstport_thieu_tra_0_khong_phai_none():
    doc = {
        "_source": {
            "id": "1.1",
            "rule": {"id": "1", "description": "d"},
            "timestamp": "2026-08-16T17:56:56.130+0000",
        }
    }
    result = parse_wazuh_alert(doc)
    assert result.alert.dst_port == 0
    assert result.alert.dst_port is not None


def test_dstip_thieu_tra_chuoi_rong_khong_phai_none():
    doc = {
        "_source": {
            "id": "1.1",
            "rule": {"id": "1", "description": "d"},
            "timestamp": "2026-08-16T17:56:56.130+0000",
        }
    }
    result = parse_wazuh_alert(doc)
    assert result.alert.dstip == ""
    assert result.alert.dstip is not None


def test_srcip_thieu_tra_chuoi_rong_khong_phai_none():
    doc = {
        "_source": {
            "id": "1.1",
            "rule": {"id": "1", "description": "d"},
            "timestamp": "2026-08-16T17:56:56.130+0000",
        }
    }
    result = parse_wazuh_alert(doc)
    assert result.alert.srcip == ""
    assert result.alert.srcip is not None


def test_ip_rong_ra_is_private_none_khong_raise():
    doc = {
        "_source": {
            "id": "1.1",
            "rule": {"id": "1", "description": "d"},
            "timestamp": "2026-08-16T17:56:56.130+0000",
        }
    }
    result = parse_wazuh_alert(doc)
    assert result.alert.srcip_is_private is None
    assert result.alert.dstip_is_private is None


def test_alert_user_uu_tien_dstuser_fallback_srcuser_khong_bao_gio_rong():
    doc_dstuser = {
        "_source": {
            "id": "1.1",
            "rule": {"id": "1", "description": "d"},
            "timestamp": "2026-08-16T17:56:56.130+0000",
            "data": {"dstuser": "root", "srcuser": "eve"},
        }
    }
    assert parse_wazuh_alert(doc_dstuser).alert.alert_user == "root"

    doc_srcuser_only = {
        "_source": {
            "id": "1.1",
            "rule": {"id": "1", "description": "d"},
            "timestamp": "2026-08-16T17:56:56.130+0000",
            "data": {"srcuser": "eve"},
        }
    }
    assert parse_wazuh_alert(doc_srcuser_only).alert.alert_user == "eve"

    doc_empty_dstuser = {
        "_source": {
            "id": "1.1",
            "rule": {"id": "1", "description": "d"},
            "timestamp": "2026-08-16T17:56:56.130+0000",
            "data": {"dstuser": "", "srcuser": "eve"},
        }
    }
    # alert_user_khong_rong (ck_alerts_alert_user_khong_rong): an empty
    # dstuser must not win over a real srcuser, and must never surface as ''.
    assert parse_wazuh_alert(doc_empty_dstuser).alert.alert_user == "eve"

    doc_missing = {
        "_source": {
            "id": "1.1",
            "rule": {"id": "1", "description": "d"},
            "timestamp": "2026-08-16T17:56:56.130+0000",
        }
    }
    result = parse_wazuh_alert(doc_missing)
    assert result.alert.alert_user is None
    assert result.alert.alert_user != ""


# ---------------------------------------------------------------------------
# Category — C5 (integration with ingest.category.resolve)
# ---------------------------------------------------------------------------


def _doc_with(mitre_ids=(), groups=(), decoder=None, dst_port=0) -> dict:
    return {
        "_source": {
            "id": "1.1",
            "rule": {
                "id": "1",
                "description": "d",
                "mitre": {"id": list(mitre_ids)},
                "groups": list(groups),
            },
            "timestamp": "2026-08-16T17:56:56.130+0000",
            "decoder": {"name": decoder} if decoder else {},
            "data": {"dstport": dst_port},
        }
    }


def test_moi_tang_phan_loai_mitre():
    result = parse_wazuh_alert(_doc_with(mitre_ids=["T1110"]))
    assert result.alert.category == "ssh_brute_force"
    assert result.alert.resolved_by == "mitre"


def test_moi_tang_phan_loai_mitre_parent():
    result = parse_wazuh_alert(_doc_with(mitre_ids=["T1110.001"]))
    assert result.alert.category == "ssh_brute_force"
    assert result.alert.resolved_by == "mitre"  # T1110.001 is itself an exact key


def test_moi_tang_phan_loai_groups():
    result = parse_wazuh_alert(_doc_with(groups=["authentication_failed"]))
    assert result.alert.category == "ssh_brute_force"
    assert result.alert.resolved_by == "rule_groups"


def test_moi_tang_phan_loai_decoder():
    result = parse_wazuh_alert(_doc_with(decoder="sshd"))
    assert result.alert.category == "ssh_brute_force"
    assert result.alert.resolved_by == "decoder"


def test_moi_tang_phan_loai_port():
    result = parse_wazuh_alert(_doc_with(dst_port=22))
    assert result.alert.category == "ssh_brute_force"
    assert result.alert.resolved_by == "dst_port"


def test_dao_thu_tu_mang_khong_doi_ket_qua():
    """R4 — reversing `groups` and `mitre.id` arrays must not change the
    resolved category."""
    forward = parse_wazuh_alert(_doc_with(mitre_ids=["T1078", "T1110"]))
    backward = parse_wazuh_alert(_doc_with(mitre_ids=["T1110", "T1078"]))
    assert forward.alert.category == backward.alert.category == "ssh_brute_force"
    assert forward.alert.categories == backward.alert.categories


def test_mau_that_ra_ssh_brute_force(canonical_hit):
    """The canonical alert's full_log reads 'Accepted password' (a successful
    login) — naive reading calls this suspicious_login; only MITRE ordering
    catches the brute-force-that-succeeded."""
    result = parse_wazuh_alert(canonical_hit)
    assert result.alert.category == "ssh_brute_force"
    assert result.alert.category != "suspicious_login"


def test_t1078_va_t1110_cung_khop_chon_t1110(canonical_hit):
    """C5 — both T1078 and T1110 are in the mapping table; T1110's priority
    (ssh_brute_force) outranks T1078's (suspicious_login)."""
    result = parse_wazuh_alert(canonical_hit)
    assert set(result.alert.mitre_ids) == {"T1078", "T1110"}
    assert result.alert.category == "ssh_brute_force"


def test_categories_sap_theo_do_uu_tien(canonical_hit):
    result = parse_wazuh_alert(canonical_hit)
    assert result.alert.categories == ("ssh_brute_force", "suspicious_login")


def test_khong_tin_hieu_nao_khop_ra_unknown():
    result = parse_wazuh_alert(_doc_with())
    assert result.rejection is None
    assert result.alert.category == "unknown"
    assert result.alert.resolved_by == "none"


def test_moi_category_deu_co_playbook(canonical_hit):
    """R5 — every category the parser can produce for these fixtures maps to
    a real file in kb/playbooks/ (the exhaustive table-vs-directory scan is
    P2-T03's test_category.py; this proves the integration path agrees)."""
    for result in (
        parse_wazuh_alert(canonical_hit),
        parse_wazuh_alert(_doc_with(mitre_ids=["T1078"])),
        parse_wazuh_alert(_doc_with(dst_port=80)),
    ):
        assert (PLAYBOOKS / f"{result.alert.category}.md").is_file()


# ---------------------------------------------------------------------------
# Cờ suy ra — C3, C4
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("ip", ["127.0.0.1", "10.1.2.3", "192.168.1.1", "169.254.1.1"])
def test_loopback_va_rfc1918_ra_private_true(ip):
    doc = {
        "_source": {
            "id": "1.1",
            "rule": {"id": "1", "description": "d"},
            "timestamp": "2026-08-16T17:56:56.130+0000",
            "data": {"srcip": ip},
        }
    }
    assert parse_wazuh_alert(doc).alert.srcip_is_private is True


def test_ip_public_ra_private_false():
    doc = {
        "_source": {
            "id": "1.1",
            "rule": {"id": "1", "description": "d"},
            "timestamp": "2026-08-16T17:56:56.130+0000",
            "data": {"srcip": "8.8.8.8"},
        }
    }
    assert parse_wazuh_alert(doc).alert.srcip_is_private is False


def test_ip_hong_ra_none_khong_raise():
    doc = {
        "_source": {
            "id": "1.1",
            "rule": {"id": "1", "description": "d"},
            "timestamp": "2026-08-16T17:56:56.130+0000",
            "data": {"srcip": "not-an-ip"},
        }
    }
    result = parse_wazuh_alert(doc)
    assert result.rejection is None
    assert result.alert.srcip_is_private is None


def test_raw_log_duoi_nguong_khong_bi_cat(canonical_hit):
    result = parse_wazuh_alert(canonical_hit)
    assert result.alert.raw_log == canonical_hit["_source"]["full_log"]
    assert result.alert.raw_log_truncated is False


def test_raw_log_vuot_1000kb_bi_cat_va_bat_co(monkeypatch):
    monkeypatch.setenv("RAW_LOG_MAX_BYTES", "20")
    doc = {
        "_source": {
            "id": "1.1",
            "rule": {"id": "1", "description": "d"},
            "timestamp": "2026-08-16T17:56:56.130+0000",
            "full_log": "x" * 50,
        }
    }
    result = parse_wazuh_alert(doc)
    assert result.alert.raw_log_truncated is True
    assert len(result.alert.raw_log.encode("utf-8")) == 20


def test_raw_log_cat_khong_lam_hong_utf8(monkeypatch):
    """Cutting mid multi-byte character backs off to the nearest valid UTF-8
    boundary instead of producing a broken string (measured in acceptance 7:
    10 bytes of 'é'*7 backs off to 5 whole characters, never a broken sixth)."""
    monkeypatch.setenv("RAW_LOG_MAX_BYTES", "10")
    doc = {
        "_source": {
            "id": "1.1",
            "rule": {"id": "1", "description": "d"},
            "timestamp": "2026-08-16T17:56:56.130+0000",
            "full_log": "é" * 7,
        }
    }
    result = parse_wazuh_alert(doc)
    assert result.alert.raw_log == "é" * 5
    assert len(result.alert.raw_log.encode("utf-8")) == 10
    assert result.alert.raw_log_truncated is True
    # decodes cleanly -- proves no broken trailing byte survived
    result.alert.raw_log.encode("utf-8").decode("utf-8")


def test_raw_payload_khong_bi_cat_du_raw_log_bi_cat(monkeypatch):
    monkeypatch.setenv("RAW_LOG_MAX_BYTES", "5")
    full_log = "x" * 100
    doc = {
        "_source": {
            "id": "1.1",
            "rule": {"id": "1", "description": "d"},
            "timestamp": "2026-08-16T17:56:56.130+0000",
            "full_log": full_log,
        }
    }
    result = parse_wazuh_alert(doc)
    assert result.alert.raw_log_truncated is True
    assert len(result.alert.raw_log) < len(full_log)
    assert result.alert.raw_payload["full_log"] == full_log  # untouched


# ---------------------------------------------------------------------------
# event_bucket_hash on the canonical alert, through the full parse path
# ---------------------------------------------------------------------------


def test_hash_mau_that_bang_76fcfceb(canonical_hit):
    result = parse_wazuh_alert(canonical_hit)
    assert result.alert.event_bucket_hash == CANONICAL_HASH


# ---------------------------------------------------------------------------
# Rejection: field name, never an exception (acceptance 6)
# ---------------------------------------------------------------------------


def test_tu_choi_neu_thieu_id():
    result = parse_wazuh_alert({"rule": {"id": "1", "description": "x"}})
    assert result.rejection == "id"
    assert "Traceback" not in (result.rejection or "")


def test_tu_choi_neu_timestamp_khong_parse_duoc():
    doc = {"id": "1", "rule": {"id": "1", "description": "x"}, "timestamp": "garbage"}
    result = parse_wazuh_alert(doc)
    assert result.rejection == "timestamp"


def test_tu_choi_khong_bao_gio_lo_ten_class_hay_stack_trace():
    for doc in (
        {"rule": {"id": "1", "description": "x"}},
        {"id": "1", "rule": {"description": "x"}, "timestamp": "2026-09-02T16:15:36.255+0700"},
        {"id": "1", "rule": {"id": "1", "description": "x"}, "timestamp": "garbage"},
    ):
        result = parse_wazuh_alert(doc)
        assert result.alert is None
        assert result.rejection in {"id", "rule.id", "timestamp"}
        for banned in ("Traceback", "Error", "Exception"):
            assert banned not in result.rejection


def test_khong_bao_gio_raise_tren_payload_gan_rong():
    """R2 — a nearly-empty payload never raises; it rejects cleanly."""
    for doc in ({}, {"_source": {}}, {"id": None}, {"rule": None}):
        result = parse_wazuh_alert(doc)  # must not raise
        assert result.alert is None
        assert isinstance(result.rejection, str)


# ---------------------------------------------------------------------------
# Determinism (R3) and the archive-line-vs-Logstash-line agreement
# ---------------------------------------------------------------------------


def test_parse_la_tat_dinh(canonical_hit):
    """R3 — the same payload always yields the same Alert."""
    r1 = parse_wazuh_alert(canonical_hit)
    r2 = parse_wazuh_alert(canonical_hit)
    assert r1.alert == r2.alert
    assert r1.envelope == r2.envelope


def test_logstash_line_va_dong_archive_goc_ra_cung_alert_time(archive_bare_doc):
    """The Logstash-shaped bare document (`@timestamp` is Logstash's *ingest*
    time, 1.3 s later — measured) and the raw archive line packed inside its
    own `event.original` must parse to the identical alert_time and identity;
    `@timestamp` itself is never read as alert_time."""
    r_logstash = parse_wazuh_alert(archive_bare_doc)
    raw_line = json.loads(archive_bare_doc["event"]["original"])
    r_raw = parse_wazuh_alert(raw_line)

    assert r_logstash.envelope == r_raw.envelope == "bare"
    assert r_logstash.alert.alert_id == r_raw.alert.alert_id
    assert r_logstash.alert.alert_time == r_raw.alert.alert_time
    assert r_logstash.alert.alert_time == datetime(2026, 9, 2, 9, 15, 36, 255_000, tzinfo=UTC)
    # the Logstash ingest timestamp is NOT the alert time
    logstash_ingest = datetime.fromisoformat(archive_bare_doc["@timestamp"])
    assert r_logstash.alert.alert_time != logstash_ingest
    assert (logstash_ingest - r_logstash.alert.alert_time).total_seconds() == pytest.approx(
        1.3, abs=0.05
    )


def test_archive_line_category_agent_manager(archive_bare_doc):
    raw_line = json.loads(archive_bare_doc["event"]["original"])
    result = parse_wazuh_alert(raw_line)
    assert result.alert.category == "ssh_brute_force"  # T1110.001, exact tier
    assert result.alert.agent_name == "user1-IA1803"
    assert result.alert.event_time is None


# ---------------------------------------------------------------------------
# The no-fields fixture: same instant, same hash, on the fallback path
# ---------------------------------------------------------------------------


def test_no_fields_hit_du_luu_fallback_khop_canonical(canonical_hit, no_fields_hit):
    """indexer_hit_no_fields.json is alert_40112.json with `fields` deleted —
    the exact difference between a hit returned with and without the
    `"fields": ["timestamp"]` search parameter (design note 5). Both must
    resolve to the same alert_time and hash despite taking different code
    paths."""
    assert "fields" in canonical_hit
    assert "fields" not in no_fields_hit
    a = parse_wazuh_alert(canonical_hit).alert
    b = parse_wazuh_alert(no_fields_hit).alert
    assert a.alert_time == b.alert_time
    assert a.event_bucket_hash == b.event_bucket_hash


def test_no_fields_hit_envelope_van_la_indexer_hit(no_fields_hit):
    """Missing `fields` does not change the envelope classification — it is
    still an indexer hit (has `_source`), just without the optional field."""
    assert parse_wazuh_alert(no_fields_hit).envelope == "indexer_hit"


# ---------------------------------------------------------------------------
# Canonical alert against its oracle (mirrors acceptance 2, as a pytest test)
# ---------------------------------------------------------------------------


def test_canonical_alert_khop_oracle(canonical_hit, canonical_expected):
    alert = parse_wazuh_alert(canonical_hit).alert

    def norm(key, value):
        if key == "alert_time" and isinstance(value, str):
            return datetime.fromisoformat(value)
        return list(value) if isinstance(value, tuple) else value

    diff = {
        key: (getattr(alert, key), expected)
        for key, expected in canonical_expected.items()
        if not key.startswith("_") and norm(key, getattr(alert, key)) != norm(key, expected)
    }
    assert diff == {}
    assert alert.event_bucket_hash == CANONICAL_HASH


def test_canonical_alert_that_bai_neu_level_doi(canonical_hit):
    """Named failing case for acceptance 2: level 12 -> 11 must change both
    severity and rule_level away from the oracle."""
    doc = json.loads(json.dumps(canonical_hit))
    doc["_source"]["rule"]["level"] = 11
    alert = parse_wazuh_alert(doc).alert
    assert alert.rule_level == 11
    assert alert.severity == "high"
    assert (alert.rule_level, alert.severity) != (12, "critical")
