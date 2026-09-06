"""Unit tests for app.infra.errors — pure, no clock/DB/network."""

from __future__ import annotations

import httpx
import psycopg
from app.infra.errors import ConfigError, PermanentError, TransientError, classify, counters


class FakeStatusAttr(Exception):
    """Mimics a custom HTTP error that carries `status_code` directly (e.g. the
    indexer probe's IndexerHTTPError), not nested under `.response`."""

    def __init__(self, status_code: int) -> None:
        self.status_code = status_code
        super().__init__(f"HTTP {status_code}")


def _httpx_status_error(status_code: int) -> httpx.HTTPStatusError:
    request = httpx.Request("GET", "https://example.invalid/")
    response = httpx.Response(status_code, request=request)
    return httpx.HTTPStatusError("boom", request=request, response=response)


class TestExceptionClasses:
    def test_transient_error_is_an_exception(self):
        assert isinstance(TransientError("x"), Exception)

    def test_permanent_error_is_an_exception(self):
        assert isinstance(PermanentError("x"), Exception)

    def test_config_error_is_an_exception(self):
        assert isinstance(ConfigError("x"), Exception)

    def test_the_three_classes_are_distinct(self):
        assert TransientError is not PermanentError
        assert TransientError is not ConfigError
        assert PermanentError is not ConfigError


class TestClassifyTransient:
    def test_transient_error_instance(self):
        assert classify(TransientError("x")) == "transient"

    def test_psycopg_operational_error(self):
        assert classify(psycopg.OperationalError("x")) == "transient"

    def test_httpx_transport_error(self):
        assert classify(httpx.ConnectError("x")) == "transient"

    def test_httpx_timeout_exception(self):
        assert classify(httpx.ReadTimeout("x")) == "transient"

    def test_http_status_500_via_response_attribute(self):
        assert classify(_httpx_status_error(500)) == "transient"

    def test_http_status_503_via_response_attribute(self):
        assert classify(_httpx_status_error(503)) == "transient"

    def test_http_status_500_via_direct_status_code_attribute(self):
        assert classify(FakeStatusAttr(500)) == "transient"


class TestClassifyPermanent:
    def test_permanent_error_instance(self):
        assert classify(PermanentError("x")) == "permanent"

    def test_value_error_from_our_own_parsing(self):
        assert classify(ValueError("x")) == "permanent"

    def test_key_error(self):
        assert classify(KeyError("x")) == "permanent"

    def test_type_error(self):
        assert classify(TypeError("x")) == "permanent"

    def test_psycopg_data_error(self):
        assert classify(psycopg.DataError("x")) == "permanent"

    def test_psycopg_integrity_error(self):
        assert classify(psycopg.IntegrityError("x")) == "permanent"

    def test_http_status_400_via_response_attribute(self):
        assert classify(_httpx_status_error(400)) == "permanent"

    def test_http_status_404_via_response_attribute(self):
        assert classify(_httpx_status_error(404)) == "permanent"

    def test_http_status_400_via_direct_status_code_attribute(self):
        assert classify(FakeStatusAttr(400)) == "permanent"


class TestClassifyUnclassified:
    def test_unclassified_defaults_to_transient(self):
        assert classify(RuntimeError("unclassified")) == "transient"

    def test_unclassified_increments_a_counter_keyed_by_class_name(self):
        before = counters().get("UNCLASSIFIED:ArithmeticError", 0)
        classify(ArithmeticError("boom"))
        after = counters()["UNCLASSIFIED:ArithmeticError"]
        assert after == before + 1

    def test_classified_exceptions_never_increment_the_counter(self):
        before = dict(counters())
        classify(TransientError("x"))
        classify(PermanentError("x"))
        classify(psycopg.OperationalError("x"))
        classify(ValueError("x"))
        after = counters()
        assert after == before

    def test_counters_returns_a_copy_not_the_live_dict(self):
        snapshot = counters()
        snapshot["UNCLASSIFIED:Injected"] = 999
        assert "UNCLASSIFIED:Injected" not in counters()

    def test_acceptance_7_sequence(self):
        """The exact sequence from the task's acceptance command 7."""
        results = [
            classify(TransientError("x")),
            classify(PermanentError("x")),
            classify(psycopg.OperationalError("x")),
            classify(ValueError("x")),
            classify(RuntimeError("x")),
        ]
        assert results == ["transient", "permanent", "transient", "permanent", "transient"]
        assert counters()["UNCLASSIFIED:RuntimeError"] >= 1


class TestNoIoAtImportTime:
    def test_no_clock_db_or_network_calls_in_source(self):
        import pathlib

        backend_root = pathlib.Path(__file__).resolve().parents[1]
        source = (backend_root / "app" / "infra" / "errors.py").read_text()
        for forbidden in ("datetime.now(", "time.time(", "psycopg.connect", "httpx.Client("):
            assert forbidden not in source, f"found {forbidden!r} in errors.py"
