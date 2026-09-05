"""Offline tests for eval/indexer_probe.py.

Every test here runs without a socket: the probe is driven through an
``httpx.MockTransport`` fed from the two recorded fixtures in
``backend/tests/fixtures/``. Nothing is marked ``live`` — the live run against
the indexer is an Owner action and is blocked until ``soc_ro`` exists
(``docs/plan/INBOX.md``, 2026-09-05 · P0 / P2 · BLOCKER).
"""

import importlib.util
import json
import sys
from pathlib import Path

import httpx
import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
PROBE_PATH = REPO_ROOT / "eval" / "indexer_probe.py"
FIXTURES = Path(__file__).resolve().parent / "fixtures"

# eval/ is a composition root outside backend/ and is not on sys.path, so the
# script is loaded by path rather than imported.
_spec = importlib.util.spec_from_file_location("indexer_probe", PROBE_PATH)
probe = importlib.util.module_from_spec(_spec)
# Registered before exec_module: `from __future__ import annotations` makes the
# dataclass resolve its field types through sys.modules[__module__] at class
# creation time, which is None for an unregistered module.
sys.modules[_spec.name] = probe
_spec.loader.exec_module(probe)


def load_fixture(name):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


CAT_ROWS = load_fixture("indexer_cat_indices.json")
SEARCH_PAGE = load_fixture("indexer_search_page.json")
HITS = SEARCH_PAGE["hits"]["hits"]


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    """No ambient INDEXER_*/PULL_* value may reach a test."""
    for key in (
        "INDEXER_URL",
        "INDEXER_USER",
        "INDEXER_PASSWORD",
        "INDEXER_CA",
        "INDEXER_INDEX",
        "PULL_START",
        "PULL_PAGE",
    ):
        monkeypatch.delenv(key, raising=False)


@pytest.fixture
def ca_file(tmp_path):
    path = tmp_path / "root-ca.pem"
    path.write_text("-----BEGIN CERTIFICATE-----\nnot a real CA\n-----END CERTIFICATE-----\n")
    return path


def set_config(monkeypatch, ca_file, password="s3cr3t-do-not-print"):
    monkeypatch.setenv("INDEXER_URL", "https://127.0.0.1:9400")
    monkeypatch.setenv("INDEXER_USER", "soc_ro")
    monkeypatch.setenv("INDEXER_PASSWORD", password)
    monkeypatch.setenv("INDEXER_CA", str(ca_file))
    monkeypatch.setenv("INDEXER_INDEX", "wazuh-alerts-*")
    monkeypatch.setenv("PULL_START", "2026-08-01")


def recording_factory(handler, seen=None):
    """A client_factory for main() that never opens a socket."""

    def factory(cfg):
        if seen is not None:
            seen.append(cfg)
        return httpx.Client(
            transport=httpx.MockTransport(handler),
            auth=httpx.BasicAuth(cfg.user, cfg.password),
        )

    return factory


def happy_handler(requests=None):
    def handler(request):
        if requests is not None:
            requests.append(request)
        if "/_cat/indices" in request.url.path:
            return httpx.Response(200, json=CAT_ROWS)
        if request.url.path.endswith("/_search"):
            return httpx.Response(200, json=SEARCH_PAGE)
        return httpx.Response(404, text="unexpected path")

    return handler


# --- the day table ---------------------------------------------------------


def test_day_table_is_parsed_and_filtered_by_since():
    summary = probe.summarize_days(CAT_ROWS, "2026-08-01")
    assert [d["date"] for d in summary["days"]] == [
        "2026-08-01",
        "2026-08-02",
        "2026-08-03",
        "2026-08-15",
        "2026-08-16",
    ]
    assert summary["total_docs"] == 269
    assert summary["days"][0]["index"] == "wazuh-alerts-4.x-2026.08.01"
    assert summary["days"][0]["docs_count"] == 52
    assert summary["days"][0]["store_size"] == "401.7kb"


def test_earliest_index_date_comes_from_the_unfiltered_set():
    summary = probe.summarize_days(CAT_ROWS, "2026-08-01")
    # 2026-07-30 is dropped from the table by --since but is still the answer
    # to "how far back does the index go", which is what sizes the G1 gold set.
    assert summary["earliest_index_date"] == "2026-07-30"
    assert "2026-07-30" not in [d["date"] for d in summary["days"]]


def test_non_matching_index_name_is_ignored():
    names = [r["index"] for r in CAT_ROWS]
    assert "wazuh-alerts-4.x-rollover-000001" in names
    summary = probe.summarize_days(CAT_ROWS, "2026-01-01")
    assert "wazuh-alerts-4.x-rollover-000001" not in [d["index"] for d in summary["days"]]
    # its 7 documents are not in the total either: 41+52+47+58+49+63 = 310
    assert summary["total_docs"] == 310


def test_format_day_table_renders_every_kept_day_and_the_total():
    text = probe.format_day_table(CAT_ROWS, "2026-08-01")
    for date in ("2026-08-01", "2026-08-02", "2026-08-03", "2026-08-15", "2026-08-16"):
        assert date in text
    assert "2026-07-30" not in text
    assert "rollover" not in text
    assert "269" in text


# --- sample picking --------------------------------------------------------


def test_pick_samples_returns_one_document_per_distinct_rule_id():
    picked = probe.pick_samples(HITS, 5)
    assert [h["_source"]["rule"]["id"] for h in picked] == ["40112", "5710", "5503"]
    # the fixture's fourth hit repeats rule 40112 and must not be picked twice
    assert len(HITS) == 4


def test_pick_samples_stops_at_n():
    picked = probe.pick_samples(HITS, 2)
    assert len(picked) == 2
    assert {h["_source"]["rule"]["id"] for h in picked} == {"40112", "5710"}
    assert probe.pick_samples(HITS, 0) == []


# --- the two requests ------------------------------------------------------


def test_fetch_index_table_asks_for_the_documented_cat_url():
    requests = []
    client = httpx.Client(transport=httpx.MockTransport(happy_handler(requests)))
    rows = probe.fetch_index_table(client, "https://127.0.0.1:9400", "wazuh-alerts-*")
    assert rows == CAT_ROWS
    url = requests[0].url
    assert url.path == "/_cat/indices/wazuh-alerts-*"
    assert dict(url.params) == {
        "format": "json",
        "h": "index,docs.count,store.size",
        "s": "index",
    }


def test_fetch_page_sends_the_search_after_body():
    requests = []
    client = httpx.Client(transport=httpx.MockTransport(happy_handler(requests)))
    probe.fetch_page(client, "https://127.0.0.1:9400", "wazuh-alerts-*", "2026-08-01", 500)
    body = json.loads(requests[0].content)
    assert body == {
        "size": 500,
        "sort": [{"timestamp": "asc"}],
        "query": {"range": {"timestamp": {"gte": "2026-08-01"}}},
    }
    assert requests[0].url.path == "/wazuh-alerts-*/_search"

    probe.fetch_page(
        client, "https://127.0.0.1:9400", "wazuh-alerts-*", "2026-08-01", 500, after=[1786903016130]
    )
    assert json.loads(requests[1].content)["search_after"] == [1786903016130]


# --- exit codes ------------------------------------------------------------


def test_empty_credentials_exit_2_and_point_at_the_blocker(monkeypatch, capsys):
    monkeypatch.setenv("INDEXER_USER", "")
    monkeypatch.setenv("INDEXER_PASSWORD", "")
    rc = probe.main(["--env-file", "/dev/null"])
    err = capsys.readouterr().err
    assert rc == 2
    assert "soc_ro" in err
    assert "docs/plan/INBOX.md" in err
    assert "INDEXER_USER" in err and "INDEXER_PASSWORD" in err


def test_every_missing_key_is_reported_in_one_message(monkeypatch, capsys):
    rc = probe.main(["--env-file", "/dev/null"])
    err = capsys.readouterr().err
    assert rc == 2
    for key in (
        "INDEXER_URL",
        "INDEXER_USER",
        "INDEXER_PASSWORD",
        "INDEXER_CA",
        "INDEXER_INDEX",
        "PULL_START",
    ):
        assert key in err


def test_unreadable_indexer_ca_exit_2(monkeypatch, capsys, tmp_path):
    set_config(monkeypatch, tmp_path / "does-not-exist.pem")
    rc = probe.main(["--env-file", "/dev/null"])
    err = capsys.readouterr().err
    assert rc == 2
    assert "INDEXER_CA" in err
    assert "does-not-exist.pem" in err


def test_transport_error_exit_3(monkeypatch, capsys, ca_file):
    set_config(monkeypatch, ca_file)

    def boom(request):
        raise httpx.ConnectError("certificate verify failed", request=request)

    rc = probe.main(["--env-file", "/dev/null"], client_factory=recording_factory(boom))
    err = capsys.readouterr().err
    assert rc == 3
    assert "ConnectError" in err
    assert "127.0.0.1:9400" in err


def test_non_2xx_status_exit_4(monkeypatch, capsys, ca_file):
    set_config(monkeypatch, ca_file)
    body = "Unauthorized" + "x" * 500

    def unauthorized(request):
        return httpx.Response(401, text=body)

    rc = probe.main(["--env-file", "/dev/null"], client_factory=recording_factory(unauthorized))
    err = capsys.readouterr().err
    assert rc == 4
    assert "401" in err
    assert "Unauthorized" in err
    # the body excerpt is capped at 300 characters
    assert body not in err


# --- the whole report ------------------------------------------------------


def test_a_run_issues_exactly_two_requests(monkeypatch, capsys, ca_file):
    """One _cat/indices and one _search — the card caps a run at two."""
    set_config(monkeypatch, ca_file)
    requests = []
    rc = probe.main(
        ["--env-file", "/dev/null"], client_factory=recording_factory(happy_handler(requests))
    )
    capsys.readouterr()
    assert rc == 0
    assert [r.url.path for r in requests] == [
        "/_cat/indices/wazuh-alerts-*",
        "/wazuh-alerts-*/_search",
    ]


def test_text_report_prints_the_three_sections(monkeypatch, capsys, ca_file):
    set_config(monkeypatch, ca_file)
    rc = probe.main(
        ["--env-file", "/dev/null", "--since", "2026-08-01", "--page", "4"],
        client_factory=recording_factory(happy_handler()),
    )
    out = capsys.readouterr().out
    assert rc == 0
    assert "timestamp" in out.splitlines()[0]  # the sort field is in the header
    assert "2026-08-16" in out
    assert "total_docs" in out and "269" in out
    assert "earliest_index_date" in out and "2026-07-30" in out
    assert "1786903016130" in out and "1786903451275" in out


def test_json_report_is_one_object_and_nothing_else(monkeypatch, capsys, ca_file):
    set_config(monkeypatch, ca_file)
    rc = probe.main(
        ["--env-file", "/dev/null", "--since", "2026-08-01", "--json"],
        client_factory=recording_factory(happy_handler()),
    )
    captured = capsys.readouterr()
    assert rc == 0
    report = json.loads(captured.out)  # a single object, nothing else on stdout
    assert report["sort_field"] == "timestamp"
    assert report["total_docs"] == 269
    assert report["earliest_index_date"] == "2026-07-30"
    assert len(report["days"]) == 5
    assert report["page"]["hits"] == 4
    assert report["page"]["first_sort"] == [1786903016130]
    assert report["page"]["last_sort"] == [1786903451275]
    assert report["page"]["first_index"] == "wazuh-alerts-4.x-2026.08.16"


def test_save_samples_writes_one_byte_faithful_file_per_rule(
    monkeypatch, capsys, ca_file, tmp_path
):
    set_config(monkeypatch, ca_file)
    out_dir = tmp_path / "fixtures"
    rc = probe.main(
        ["--env-file", "/dev/null", "--save-samples", "5", "--samples-dir", str(out_dir)],
        client_factory=recording_factory(happy_handler()),
    )
    assert rc == 0
    written = sorted(p.name for p in out_dir.iterdir())
    assert written == [
        "indexer_sample_rule40112.json",
        "indexer_sample_rule5503.json",
        "indexer_sample_rule5710.json",
    ]
    saved = json.loads((out_dir / "indexer_sample_rule40112.json").read_text(encoding="utf-8"))
    assert saved == HITS[0]
    assert str(out_dir / "indexer_sample_rule40112.json") in capsys.readouterr().out


def test_the_password_is_never_printed_or_saved(monkeypatch, capsys, ca_file, tmp_path):
    secret = "correct-horse-battery-staple"
    set_config(monkeypatch, ca_file, password=secret)
    out_dir = tmp_path / "fixtures"
    probe.main(
        ["--env-file", "/dev/null", "--save-samples", "5", "--samples-dir", str(out_dir)],
        client_factory=recording_factory(happy_handler()),
    )
    captured = capsys.readouterr()
    assert secret not in captured.out
    assert secret not in captured.err
    for path in out_dir.iterdir():
        assert secret not in path.read_text(encoding="utf-8")


# --- the invariant a Reviewer greps for ------------------------------------


def test_the_source_offers_no_way_to_disable_tls_verification():
    source = PROBE_PATH.read_text(encoding="utf-8")
    for forbidden in (
        "verify=False",
        "verify=0",
        "--insecure",
        "--no-verify",
        "ssl._create_unverified_context",
    ):
        assert forbidden not in source, f"{forbidden} must never appear in {PROBE_PATH.name}"
