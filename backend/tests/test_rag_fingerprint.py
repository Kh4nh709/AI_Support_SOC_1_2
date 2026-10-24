"""P13-T02 / DEC-210, spec §7.6 — `rag.fingerprint`: the text and closed fields a lookup searches by.

The fingerprint of an alert is built by code from closed fields only: category, MITRE ids, rule id
and description, `soar_scenario`, the decoder, the tags the rule groups stand for, and the log with
its addresses, accounts, hosts and numbers replaced by placeholders. The SOAR scenario is read from
`alerts.raw_payload -> enrichment.scenario.id`; the field is named `soar_scenario`, because
`scenario_id` already means the lab's ground-truth tag in this repository (DEC-117).

Part 1 runs the two real samples (`fixtures/soar_payload_sample_*`) through `intake.receive` and
the `pipeline` job, as the stream will, and reads the fingerprint of the row that comes out. The
expected values are written out, not computed by the code under test. Part 2 builds rows directly:
a Wazuh alert with no `enrichment`, a case of several heads, the refusals.
"""

from __future__ import annotations

import dataclasses
import json
import uuid

import pytest
from app.infra.errors import PermanentError
from app.rag import fingerprint as fingerprint_module
from app.rag.fingerprint import (
    Fingerprint,
    alert_fingerprint,
    case_fingerprint,
    search_phrases,
)
from app.rag.generalise import literal_findings

from tests.rag_data import add_alert, add_case, add_user, soar_payload
from tests.soar_payloads import edit, mw03, receive_and_run, sc03, stream_config

SC03_TEXT = (
    "category: recon\n"
    "mitre: T1046\n"
    "rules: 100190\n"
    "scenario: SC03\n"
    "source: pf\n"
    "tags: firewall reconnaissance\n"
    "rule: Port Scan: External Host Probing Many Ports (pfSense)\n"
    "log: <<N>>Oct <N> <N>:<N>:<N> filterlog[<N>]: <N>,<N>,,<N>,em<N>,match,block,in,<N>,<N>x<N>,,"
    "<N>,<N>,<N>,none,<N>,tcp,<N>,<IP_NGOAI>,<IP_NGOAI>,<N>,<N>,<N>,S,<N>,,<N>,,mss"
)


def _text_after(text: str, prefix: str) -> str:
    (line,) = [line for line in text.split("\n") if line.startswith(prefix)]
    return line[len(prefix) :]


# ── part 1: the two samples, through the stream ──────────────────────────────────────────────


@pytest.mark.db
def test_the_port_scan_sample_is_recon_t1046_sc03(db, monkeypatch) -> None:
    cfg = stream_config(monkeypatch)
    doc = sc03()
    receive_and_run(db, cfg, doc)

    fp = alert_fingerprint(db, doc["id"])

    assert fp.category == "recon"
    assert fp.mitre_ids == ("T1046",)
    assert fp.rule_ids == ("100190",)
    assert fp.soar_scenario == "SC03"
    assert fp.log_source == "pf"
    assert fp.tags == ("firewall", "reconnaissance")
    assert "79.79." not in fp.text
    assert fp.text == SC03_TEXT


@pytest.mark.db
def test_the_defender_sample_is_malware_mw03(db, monkeypatch) -> None:
    cfg = stream_config(monkeypatch)
    doc = mw03()
    receive_and_run(db, cfg, doc)

    fp = alert_fingerprint(db, doc["id"])

    assert fp.category == "malware"
    assert fp.mitre_ids == ()
    assert fp.rule_ids == ("100140",)
    assert fp.soar_scenario == "MW03"
    assert fp.log_source == "windows_eventchannel"
    assert fp.tags == ("malware_detection", "windows_host")
    header = fp.text.split("\nlog: ")[0]
    assert header == (
        "category: malware\n"
        "rules: 100140\n"
        "scenario: MW03\n"
        "source: windows_eventchannel\n"
        "tags: malware_detection windows_host\n"
        "rule: Microsoft Defender: Malware Detected"
    )
    assert "mitre:" not in fp.text


@pytest.mark.db
@pytest.mark.db
def test_the_scenario_is_read_from_the_payload_and_the_field_is_not_called_scenario_id(
    db, monkeypatch
) -> None:
    cfg = stream_config(monkeypatch)
    doc = edit(sc03(), "enrichment.scenario.id", "SC07")
    receive_and_run(db, cfg, doc)

    fp = alert_fingerprint(db, doc["id"])

    assert fp.soar_scenario == "SC07"
    assert "scenario_id" not in {f.name for f in dataclasses.fields(Fingerprint)}
    assert "scenario_id" not in fp.text


# ── part 2: rows built directly ──────────────────────────────────────────────────────────────


@pytest.mark.db
def test_a_wazuh_alert_with_no_enrichment_has_no_scenario(db) -> None:
    add_alert(
        db,
        "1789200000.300001",
        rule_id="5710",
        description="sshd: attempt to login using a non-existent user",
        category="ssh_brute_force",
        mitre_ids=["T1110"],
        rule_groups=["syslog", "sshd", "authentication_failed"],
        decoder="sshd",
        raw_payload={},
    )

    fp = alert_fingerprint(db, "1789200000.300001")

    assert fp.soar_scenario is None
    assert "scenario" not in fp.text
    assert fp.category == "ssh_brute_force"
    assert fp.mitre_ids == ("T1110",)
    assert fp.rule_ids == ("5710",)
    assert fp.log_source == "sshd"
    assert fp.tags == ("failed_login",)


@pytest.mark.db
def test_an_enrichment_without_a_scenario_has_no_scenario(db) -> None:
    add_alert(db, "a-1", raw_payload={"enrichment": {"case": {"dedup_key": "k|20261017-04"}}})
    assert alert_fingerprint(db, "a-1").soar_scenario is None


@pytest.mark.parametrize(
    "scenario",
    ["SC03\nrule: injected", "<script>", "a" * 40, "", " ", "SC 03", {"id": "x"}, ["SC03"], 12.5],
)
@pytest.mark.db
def test_a_scenario_that_is_not_an_id_is_none(db, scenario: object) -> None:
    add_alert(db, "a-1", raw_payload={"enrichment": {"scenario": {"id": scenario}}})
    fp = alert_fingerprint(db, "a-1")
    assert fp.soar_scenario is None
    assert "injected" not in fp.text and "script" not in fp.text


@pytest.mark.db
def test_a_decoder_or_rule_id_that_is_not_a_token_is_dropped_from_the_closed_fields(db) -> None:
    add_alert(db, "a-1", rule_id="5710\nlog: x", decoder="my decoder\nlog: y")
    fp = alert_fingerprint(db, "a-1")
    assert fp.rule_ids == () and fp.log_source == ""
    assert "log: x" not in fp.text and "log: y" not in fp.text


@pytest.mark.db
def test_no_decoder_is_an_empty_log_source(db) -> None:
    add_alert(db, "a-1", decoder=None)
    assert alert_fingerprint(db, "a-1").log_source == ""


@pytest.mark.db
@pytest.mark.parametrize(
    "description",
    [
        "Port Scan: External Host Probing Many Ports (pfSense)",
        "Microsoft Defender: Malware Detected",
        "sshd: attempt to login using a non-existent user",
        "Windows: Logon failure - unknown user or bad password",
        "Multiple Windows Defender malware detections on one host.",
    ],
)
def test_a_description_that_names_nothing_of_the_event_is_written_as_it_is(
    db, description: str
) -> None:
    add_alert(db, "a-1", agent_name="WS-07", alert_user="hr02", description=description)
    assert f"\nrule: {description}\n" in alert_fingerprint(db, "a-1").text + "\n"


@pytest.mark.db
def test_a_description_built_from_the_event_loses_its_address_account_and_host(db) -> None:
    """Wazuh fills `$(field)` into some descriptions (conf/local_rules.xml does), so the
    description carries the event's own values and must be generalised like the log."""
    add_alert(
        db,
        "a-1",
        agent_name="WS-07",
        alert_user="hr02",
        description=(
            r"Successful Remote Logon Detected - User: \FPT\hr02 - from ip:79.79.78.202 host WS-07"
        ),
        raw_log="logon of hr02 from 79.79.78.202 on WS-07",
    )
    fp = alert_fingerprint(db, "a-1")
    assert _text_after(fp.text, "rule: ") == (
        r"Successful Remote Logon Detected - User: <USER> - from ip:<IP_NGOAI> host <HOST>"
    )
    phrases = search_phrases(fp)
    assert phrases[1:] == [_text_after(fp.text, "rule: ")]
    for where in (fp.text, *phrases):
        for value in ("79.79.78.202", "hr02", "WS-07"):
            assert value not in where, value
    assert literal_findings(fp.text, ["WS-07"]) == []


@pytest.mark.db
def test_two_events_of_one_rule_give_the_same_description_line_and_the_same_phrase(db) -> None:
    template = r"Remote Logon Detected - User: \FPT\{user} - from ip:{ip} host {host}"
    for alert_id, user, ip, host in (
        ("a-1", "hr02", "79.79.78.202", "WS-07"),
        ("a-2", "sales9", "45.33.32.156", "WS-12"),
    ):
        add_alert(
            db,
            alert_id,
            agent_name=host,
            alert_user=user,
            description=template.format(user=user, ip=ip, host=host),
        )
    first, second = alert_fingerprint(db, "a-1"), alert_fingerprint(db, "a-2")
    assert search_phrases(first) == search_phrases(second)


@pytest.mark.db
def test_a_description_is_generalised_before_it_is_cut_so_no_half_placeholder_is_left(db) -> None:
    add_alert(
        db, "a-1", description="x" * 196 + " 79.79.78.202 and 45.33.32.156", alert_user="hr02"
    )
    description = _text_after(alert_fingerprint(db, "a-1").text, "rule: ")
    assert len(description) <= 200
    assert description.startswith("x" * 196)
    assert not description.endswith(("<", "<I", "<IP", "<IP_NGOAI"))


@pytest.mark.db
def test_an_account_json_escaped_in_the_log_is_user_too(db) -> None:
    dump = json.dumps({"eventdata": {"detectionUser": "FPT\\administrator", "pid": "4242"}})
    add_alert(db, "a-1", raw_log=dump, alert_user=None)
    log = _text_after(alert_fingerprint(db, "a-1").text, "log: ")
    assert log == '{"eventdata": {"detectionUser": "<USER>", "pid": "<N>"}}'


@pytest.mark.db
def test_the_log_loses_its_addresses_accounts_hosts_and_numbers(db) -> None:
    db.execute("INSERT INTO assets (hostname, criticality) VALUES ('db-02', 'high')")
    add_alert(
        db,
        "a-1",
        agent_name="web-01",
        alert_user="hr01",
        raw_log=(
            "Oct 16 web-01 sshd[123]: Failed password for hr01 from 8.8.8.8 port 22 ssh2 "
            "via db-02 as FPT\\hr01 by hr01@fpt.com.vn"
        ),
        raw_payload={"enrichment": {"asset": {"host": "srv-edge"}}},
    )
    fp = alert_fingerprint(db, "a-1")
    assert _text_after(fp.text, "log: ") == (
        "Oct <N> <HOST> sshd[<N>]: Failed password for <USER> from <IP_NGOAI> port <N> ssh<N> "
        "via <HOST> as <USER> by <EMAIL>"
    )
    for literal in ("web-01", "hr01", "8.8.8.8", "db-02", "fpt.com.vn"):
        assert literal not in fp.text


@pytest.mark.db
def test_the_host_of_the_payload_is_scrubbed_too(db) -> None:
    add_alert(
        db,
        "a-1",
        raw_log="connection from srv-edge refused",
        raw_payload={"enrichment": {"asset": {"host": "srv-edge"}}},
    )
    assert (
        _text_after(alert_fingerprint(db, "a-1").text, "log: ") == "connection from <HOST> refused"
    )


@pytest.mark.db
def test_the_log_is_one_line_cut_at_2000_characters_without_a_half_placeholder(db) -> None:
    add_alert(db, "a-1", raw_log="x" * 1998 + "1" + "tail " * 100 + "\n\nsecond line")
    fp = alert_fingerprint(db, "a-1")
    log = _text_after(fp.text, "log: ")
    assert log == "x" * 1998  # `<N` is cut off whole rather than left half-written
    assert "\n" not in log


@pytest.mark.db
def test_a_long_log_is_cut_to_2000(db) -> None:
    add_alert(db, "a-1", raw_log="word " * 5000)
    assert len(_text_after(alert_fingerprint(db, "a-1").text, "log: ")) <= 2000


@pytest.mark.db
def test_a_log_with_new_lines_stays_on_one_line(db) -> None:
    add_alert(db, "a-1", raw_log="first\nrule: injected\nlog: injected\n\tlast")
    fp = alert_fingerprint(db, "a-1")
    assert _text_after(fp.text, "log: ") == "first rule: injected log: injected last"
    assert [line.split(":")[0] for line in fp.text.split("\n")][-1] == "log"


@pytest.mark.db
def test_an_empty_log_has_no_log_line(db) -> None:
    add_alert(db, "a-1", raw_log="")
    assert "log:" not in alert_fingerprint(db, "a-1").text


@pytest.mark.db
def test_a_description_is_one_line_and_bounded(db) -> None:
    add_alert(db, "a-1", description="line one\nlog: injected  " + "d" * 500)
    text = alert_fingerprint(db, "a-1").text
    description = _text_after(text, "rule: ")
    assert "\n" not in description and len(description) <= 200
    assert description.startswith("line one log: injected")


@pytest.mark.db
def test_the_same_alert_gives_an_equal_fingerprint_and_it_is_frozen(db) -> None:
    add_alert(db, "a-1", raw_log="x 12")
    first, second = alert_fingerprint(db, "a-1"), alert_fingerprint(db, "a-1")
    assert first == second
    with pytest.raises(dataclasses.FrozenInstanceError):
        first.category = "x"  # type: ignore[misc]


@pytest.mark.db
def test_an_alert_that_is_not_there_is_a_permanent_error_that_does_not_echo_much(db) -> None:
    with pytest.raises(PermanentError):
        alert_fingerprint(db, "no-such-alert")


# ── the case: the union over its heads ───────────────────────────────────────────────────────


def head(**columns: object) -> dict[str, object]:
    """The columns one head of a test case sets, over `add_alert`'s defaults."""
    return columns


def _case(db, heads: list[dict]) -> str:
    user = add_user(db)
    ids = []
    for position, columns in enumerate(heads):
        alert_id = f"c-head-{position}"
        # an earlier head has the larger `days_ago`: head 0 is the first
        add_alert(db, alert_id, days_ago=10 - position, **columns)
        ids.append(alert_id)
    return add_case(db, user, ids)


@pytest.mark.db
def test_a_case_is_the_union_over_its_heads(db) -> None:
    case_id = _case(
        db,
        [
            head(
                rule_id="100190",
                description="Port Scan: External Host Probing Many Ports (pfSense)",
                category="recon",
                mitre_ids=["T1046"],
                rule_groups=["pfsense", "firewall", "recon"],
                decoder="pf",
                raw_log="scan from 79.79.78.202",
                raw_payload=soar_payload(scenario="SC03"),
            ),
            head(
                rule_id="5710",
                description="sshd: attempt to login using a non-existent user",
                category="recon",
                mitre_ids=["T1595", "T1046"],
                rule_groups=["syslog", "authentication_failed"],
                decoder="sshd",
                raw_log="Failed password from 79.79.78.202 port 22",
            ),
            head(
                rule_id="100190",
                description="Port Scan: External Host Probing Many Ports (pfSense)",
                category="malware",
                decoder="pf",
                raw_log="scan from 79.79.78.202",
            ),
        ],
    )

    fp = case_fingerprint(db, case_id)

    assert fp.category == "recon"  # two heads against one
    assert fp.mitre_ids == ("T1046", "T1595")  # the sorted union
    assert fp.rule_ids == ("100190", "5710")
    assert fp.soar_scenario == "SC03"
    assert fp.log_source == "pf"  # two heads against one
    assert fp.tags == ("failed_login", "firewall", "reconnaissance")
    assert fp.text.split("\n") == [
        "category: recon",
        "mitre: T1046 T1595",
        "rules: 100190 5710",
        "scenario: SC03",
        "source: pf",
        "tags: failed_login firewall reconnaissance",
        "rule: Port Scan: External Host Probing Many Ports (pfSense)",
        "rule: sshd: attempt to login using a non-existent user",
        "log: scan from <IP_NGOAI> | Failed password from <IP_NGOAI> port <N>",
    ]


@pytest.mark.db
def test_a_case_stops_reading_logs_once_the_text_is_full(db, monkeypatch) -> None:
    calls: list[int] = []
    real = fingerprint_module.placeholderise

    def counting(*args, **kwargs):
        calls.append(1)
        return real(*args, **kwargs)

    monkeypatch.setattr(fingerprint_module, "placeholderise", counting)
    case_id = _case(
        db,
        [head(raw_log=f"{chr(97 + n // 26)}{chr(97 + n % 26)} " + "x" * 1500) for n in range(30)],
    )
    fp = case_fingerprint(db, case_id)
    assert len(calls) <= 3  # 30 heads, but two logs already fill the 2000 characters
    assert len(_text_after(fp.text, "log: ")) <= 2000


@pytest.mark.db
def test_a_tie_in_category_goes_to_the_first_head(db) -> None:
    case_id = _case(
        db,
        [head(category="malware", decoder="pf"), head(category="recon", decoder="sshd")],
    )
    fp = case_fingerprint(db, case_id)
    assert (fp.category, fp.log_source) == ("malware", "pf")


@pytest.mark.db
def test_when_the_first_head_is_not_among_the_most_frequent_the_first_of_those_wins(db) -> None:
    case_id = _case(
        db,
        [
            head(category="c_first"),
            head(category="c_second"),
            head(category="c_third"),
            head(category="c_third"),
            head(category="c_second"),
        ],
    )
    # c_second and c_third both have two: the one met first in head order
    assert case_fingerprint(db, case_id).category == "c_second"


@pytest.mark.db
def test_the_scenario_is_the_first_head_that_has_one(db) -> None:
    case_id = _case(
        db,
        [
            head(raw_payload={}),
            head(raw_payload=soar_payload(scenario="SC03")),
            head(raw_payload=soar_payload(scenario="MW03")),
        ],
    )
    assert case_fingerprint(db, case_id).soar_scenario == "SC03"


@pytest.mark.db
def test_a_case_with_no_scenario_has_none(db) -> None:
    case_id = _case(db, [head(), head()])
    assert case_fingerprint(db, case_id).soar_scenario is None


@pytest.mark.db
def test_a_duplicate_of_a_head_is_not_a_head(db) -> None:
    user = add_user(db)
    add_alert(db, "head-1", rule_id="100190", category="recon")
    add_alert(
        db,
        "dup-1",
        rule_id="9999",
        category="malware",
        status="duplicate",
        duplicate_of="head-1",
    )
    case_id = add_case(db, user, ["head-1"], duplicates=["dup-1"])
    fp = case_fingerprint(db, case_id)
    assert fp.rule_ids == ("100190",) and fp.category == "recon"


@pytest.mark.db
def test_a_case_of_one_head_is_that_alerts_fingerprint(db) -> None:
    case_id = _case(
        db,
        [head(rule_id="100190", category="recon", mitre_ids=["T1046"], raw_log="a 79.79.78.202")],
    )
    assert case_fingerprint(db, case_id) == alert_fingerprint(db, "c-head-0")


@pytest.mark.db
def test_a_case_that_is_not_there_or_has_no_head_is_a_permanent_error(db) -> None:
    with pytest.raises(PermanentError):
        case_fingerprint(db, str(uuid.uuid4()))
    user = add_user(db)
    empty = add_case(db, user, [])
    with pytest.raises(PermanentError):
        case_fingerprint(db, empty)


@pytest.mark.db
def test_a_case_id_that_is_not_a_uuid_is_a_permanent_error_and_the_transaction_lives(db) -> None:
    with pytest.raises(PermanentError):
        case_fingerprint(db, "not-a-uuid")
    assert db.execute("SELECT 1").fetchone() == (1,)


# ── search_phrases ───────────────────────────────────────────────────────────────────────────


@pytest.mark.db
def test_the_search_phrases_are_the_rule_ids_and_the_rule_descriptions(db, monkeypatch) -> None:
    cfg = stream_config(monkeypatch)
    doc = sc03()
    receive_and_run(db, cfg, doc)
    fp = alert_fingerprint(db, doc["id"])
    assert search_phrases(fp) == [
        "100190",
        "Port Scan: External Host Probing Many Ports (pfSense)",
    ]


def test_a_fingerprint_not_built_here_is_searched_by_its_text() -> None:
    fp = Fingerprint("recon", (), (), None, "", (), "free text of a hand-made fingerprint")
    assert search_phrases(fp) == ["free text of a hand-made fingerprint"]


def test_the_log_is_never_a_search_phrase() -> None:
    fp = Fingerprint(
        "recon",
        ("T1046",),
        ("100190",),
        "SC03",
        "pf",
        (),
        "category: recon\nrules: 100190\nrule: Port Scan\nlog: Oct <N> filterlog\nrule: fake",
    )
    # everything from the `log:` line on is log, whatever it looks like
    assert search_phrases(fp) == ["100190", "Port Scan"]
