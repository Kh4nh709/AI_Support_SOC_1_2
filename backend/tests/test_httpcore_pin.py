"""SR-T1 final round (5) — `httpcore` is imported directly, so it is pinned, and the one private thing the code leans on is checked.

`infra/n8n_approval.py` bounds the call to n8n as a whole by giving the client a network backend of its own: it builds an
`httpcore.ConnectionPool` on `_DeadlineBackend` and puts it where `httpx.HTTPTransport` keeps its own (`transport._pool`, a private
attribute). `httpcore` is httpx's own dependency, but the code now imports it, and `_pool` is not a public name: an upgrade of either
must fail HERE, with a message that says what to look at, and not as a call to n8n that is quietly no longer bounded.

Pure: reads `backend/requirements.txt` and the installed packages.
"""

from __future__ import annotations

import pathlib
import re

import httpcore
import httpx

REQUIREMENTS = pathlib.Path(__file__).resolve().parents[1] / "requirements.txt"
SOURCE = pathlib.Path(__file__).resolve().parents[1] / "app" / "infra" / "n8n_approval.py"


def _pin() -> tuple[str, str]:
    """`(version, the whole line)` of the httpcore pin in `backend/requirements.txt`."""
    for line in REQUIREMENTS.read_text(encoding="utf-8").splitlines():
        match = re.match(r"httpcore==([0-9][0-9A-Za-z.]*)", line)
        if match:
            return match.group(1), line
    raise AssertionError(
        "backend/requirements.txt does not pin httpcore (`httpcore==X.Y.Z`): infra/n8n_approval.py imports it directly"
    )


def test_httpcore_is_pinned_exactly_with_a_comment_naming_the_module_that_needs_it():
    version, line = _pin()
    assert re.fullmatch(
        r"[0-9]+\.[0-9]+\.[0-9]+", version
    ), f"httpcore must be pinned to a full version, not {version!r}"
    assert "infra/n8n_approval.py" in line, "the pin's comment must name infra/n8n_approval.py"


def test_the_code_really_does_import_httpcore_directly():
    text = SOURCE.read_text(encoding="utf-8")
    assert re.search(
        r"(?m)^import httpcore$", text
    ), "n8n_approval.py no longer imports httpcore: the pin may go"


def test_the_installed_httpcore_has_the_pinned_major_version():
    pinned, _ = _pin()
    installed = httpcore.__version__
    assert installed.split(".")[0] == pinned.split(".")[0], (
        f"httpcore {installed} is installed but backend/requirements.txt pins {pinned}: the major version differs. "
        "infra/n8n_approval.py builds an httpcore.ConnectionPool on its own NetworkBackend (the bound on the whole call to n8n): "
        "read the new httpcore's NetworkBackend and NetworkStream interfaces, then update the pin and this test."
    )


def test_the_installed_httpcore_is_the_pinned_version_exactly():
    pinned, _ = _pin()
    assert (
        httpcore.__version__ == pinned
    ), f"httpcore {httpcore.__version__} is installed but requirements.txt pins {pinned}: the build is not reproducible"


def test_httpx_transport_still_keeps_its_pool_where_the_client_replaces_it():
    transport = httpx.HTTPTransport()
    try:
        assert hasattr(transport, "_pool"), (
            f"httpx {httpx.__version__}: HTTPTransport has no `_pool` any more. infra/n8n_approval.py `_build_client` replaces "
            "transport._pool with an httpcore.ConnectionPool on a network backend that bounds the whole call: without it the call "
            "to n8n is bounded only per wait. Find where this httpx keeps its pool, or give the transport the backend another way."
        )
        assert isinstance(transport._pool, httpcore.ConnectionPool), (
            f"httpx {httpx.__version__}: HTTPTransport._pool is a {type(transport._pool).__name__}, not an httpcore.ConnectionPool; "
            "infra/n8n_approval.py `_build_client` assumes it can replace it with one."
        )
        assert callable(getattr(transport._pool, "close", None))
    finally:
        transport.close()


def test_the_real_client_is_built_on_the_bounded_backend():
    import time

    from app.infra import n8n_approval

    client = n8n_approval._build_client(time.monotonic() + 5)
    try:
        pool = client._transport._pool
        assert isinstance(pool, httpcore.ConnectionPool)
        assert isinstance(
            pool._network_backend, n8n_approval._DeadlineBackend
        ), "the real client no longer runs on _DeadlineBackend: the call to n8n is not bounded as a whole"
    finally:
        client.close()
