"""`scripts/ui_e2e_scan.py`, the secret scan that ends `make ui-e2e` (P10-T12; P10-T17 item 8c).

The scan looks in a run's leavings for the run's own secrets, a DSN and a session-token shape. Playwright's
HTML report keeps what a run recorded (traces included) as a base64 zip in a `data:` URI inside `index.html`
(`<script>window.playwrightReportBase64 = "data:application/zip;base64,..."`), so a secret in a trace is
invisible to a scan of the raw bytes: not a literal, and not a zip either. A run asked for that reporter
(`PW_ARGS=--reporter=html`) would pass the scan with the secret inside it. The scan therefore decodes every
base64 `data:` payload it finds in a file and scans the decoded bytes, a zip included, to the same depth as
a zip on disk.

PURE. No database, no socket: temporary files only. A found value is never printed (each test checks it).
"""

from __future__ import annotations

import base64
import io
import pathlib
import sys
import zipfile

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))
import ui_e2e_scan

SECRET = "run-secret-0123456789abcdef"  # at least MIN_NEEDLE characters


@pytest.fixture(autouse=True)
def _the_runs_secrets(monkeypatch):
    for name in ui_e2e_scan.NEEDLE_VARS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("E2E_T1_PASSWORD", SECRET)


def _zip(members: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def _report_html(payload: bytes, mime: str = "application/zip") -> bytes:
    """What the HTML reporter writes: the report's data, as a base64 `data:` URI in a script."""
    uri = f"data:{mime};base64," + base64.b64encode(payload).decode("ascii")
    return (
        '<!DOCTYPE html><html><body><div id="root"></div>'
        f'<script>window.playwrightReportBase64 = "{uri}";</script></body></html>'
    ).encode()


def _scan(tmp_path, capsys, files: dict[str, bytes]) -> tuple[int, str]:
    for name, data in files.items():
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    capsys.readouterr()
    code = ui_e2e_scan.main([str(tmp_path)])
    return code, capsys.readouterr().out


def _says_found_without_the_value(out: str, name: str) -> None:
    assert "secret found" in out
    assert name in out
    assert SECRET not in out
    assert "postgresql://" not in out


def test_a_clean_tree_passes(tmp_path, capsys):
    code, out = _scan(tmp_path, capsys, {"a.txt": b"nothing to see", "b/c.log": b"ok"})
    assert code == 0
    assert "no secret in 2 file(s)" in out


def test_a_secret_in_a_file_is_found_and_not_printed(tmp_path, capsys):
    code, out = _scan(tmp_path, capsys, {"run.log": f"password={SECRET}".encode()})
    assert code == 1
    _says_found_without_the_value(out, "run.log")


def test_a_secret_in_a_zip_member_and_in_a_zip_in_a_zip_is_found(tmp_path, capsys):
    trace = _zip({"0-trace.network": f"X-Api-Key: {SECRET}".encode()})
    code, out = _scan(
        tmp_path,
        capsys,
        {
            "trace.zip": _zip({"trace.network": SECRET.encode()}),
            "nested.zip": _zip({"t.zip": trace}),
        },
    )
    assert code == 1
    _says_found_without_the_value(out, "trace.zip")
    _says_found_without_the_value(out, "nested.zip")


def test_a_secret_in_the_html_reports_embedded_zip_is_found(tmp_path, capsys):
    report = _report_html(_zip({"report.json": f'{{"typed": "{SECRET}"}}'.encode()}))
    assert (
        SECRET.encode() not in report
    )  # the raw bytes of the file do not show it: that is the gap
    code, out = _scan(tmp_path, capsys, {"playwright-report/index.html": report})
    assert code == 1
    _says_found_without_the_value(out, "index.html")


def test_a_secret_in_a_trace_inside_the_reports_zip_is_found(tmp_path, capsys):
    """The report's zip holds the attachments, and a trace is a zip: the depth is the one of a zip on disk."""
    trace = _zip({"0-trace.trace": f"fill: {SECRET}".encode()})
    report = _report_html(_zip({"report.json": b"{}", "data/abc.zip": trace}))
    code, out = _scan(tmp_path, capsys, {"playwright-report/index.html": report})
    assert code == 1
    _says_found_without_the_value(out, "index.html")


@pytest.mark.parametrize("mime", ["text/plain", "application/json", "application/octet-stream"])
def test_a_secret_in_any_base64_data_uri_is_found(tmp_path, capsys, mime):
    code, out = _scan(
        tmp_path,
        capsys,
        {"index.html": _report_html(f"dsn postgresql://u:{SECRET}@h/db".encode(), mime)},
    )
    assert code == 1
    _says_found_without_the_value(out, "index.html")


def test_a_clean_report_passes(tmp_path, capsys):
    report = _report_html(_zip({"report.json": b'{"tests": 3, "passed": 3}'}))
    code, out = _scan(tmp_path, capsys, {"playwright-report/index.html": report})
    assert code == 0
    assert "no secret in 1 file(s)" in out


def test_a_payload_that_is_not_base64_or_not_a_zip_does_not_stop_the_scan(tmp_path, capsys):
    page = (
        b'<script>var a = "data:application/zip;base64,@@@@@@@@@@@@@@@@@@@@@@@@";'
        b'var b = "data:application/zip;base64,'
        + base64.b64encode(b"PK\x03\x04 not a zip at all")
        + b'";'
        b'var c = "data:image/png;base64,iVBORw0KGgo=";</script>'
    )
    code, out = _scan(tmp_path, capsys, {"index.html": page, "run.log": SECRET.encode()})
    assert code == 1
    assert "run.log" in out  # the file after the odd one is still scanned
    assert "index.html" not in out
    assert SECRET not in out
