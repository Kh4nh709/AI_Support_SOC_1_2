"""The secret scan that ends `make ui-e2e` (P10-T12).

    ui_e2e_scan.py PATH...

Looks in every file under the paths given (a directory is walked; a path that does not exist is skipped; a zip
is opened and its members are read, since a Playwright trace is one) for what must never be in a test result
or in the output of a run:

  * the run's own secrets, read from the environment (E2E_JWT_SECRET, E2E_WEBHOOK_API_KEY, E2E_T1_PASSWORD,
    E2E_T2_PASSWORD, E2E_T2B_PASSWORD, and E2E_SCAN_PGPASSWORD, the password of the test cluster when it is
    long enough to be told from ordinary text);
  * a DSN (`postgresql://`, `postgres://`);
  * something shaped like a session token (three dot-separated base64url parts starting `eyJ`) or a
    `Bearer` header.

It prints the name of each file that holds one and the words "secret found", and exits 1; it never prints what
it found, nor which of the patterns matched, nor a line of the file. Exit 0 and one line when nothing is found.
"""

from __future__ import annotations

import io
import os
import re
import sys
import zipfile
from pathlib import Path

NEEDLE_VARS = (
    "E2E_JWT_SECRET",
    "E2E_WEBHOOK_API_KEY",
    "E2E_T1_PASSWORD",
    "E2E_T2_PASSWORD",
    "E2E_T2B_PASSWORD",
    "E2E_SCAN_PGPASSWORD",
)
# A shorter needle would match ordinary text (a cluster password of "postgres" is in every log).
MIN_NEEDLE = 12

LITERALS = (b"postgresql://", b"postgres://")
SHAPES = (
    re.compile(rb"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*"),
    re.compile(rb"[Bb]earer\s+[A-Za-z0-9._~+/=-]{16,}"),
)
MAX_MEMBER = 256 * 1024 * 1024


def needles() -> list[bytes]:
    found = []
    for name in NEEDLE_VARS:
        value = os.environ.get(name, "")
        if len(value) >= MIN_NEEDLE:
            found.append(value.encode("utf-8"))
    return found


def holds_secret(data: bytes, secrets: list[bytes]) -> bool:
    if any(secret in data for secret in secrets):
        return True
    if any(literal in data for literal in LITERALS):
        return True
    return any(shape.search(data) for shape in SHAPES)


def scan_bytes(data: bytes, secrets: list[bytes], depth: int = 0) -> bool:
    if holds_secret(data, secrets):
        return True
    if depth < 2 and data[:4] == b"PK\x03\x04":
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                for member in archive.infolist():
                    if member.is_dir() or member.file_size > MAX_MEMBER:
                        continue
                    if scan_bytes(archive.read(member), secrets, depth + 1):
                        return True
        except (zipfile.BadZipFile, OSError, RuntimeError, NotImplementedError):
            return False
    return False


def files_under(paths: list[str]) -> list[Path]:
    files: list[Path] = []
    for raw in paths:
        path = Path(raw)
        if path.is_dir():
            files.extend(p for p in sorted(path.rglob("*")) if p.is_file())
        elif path.is_file():
            files.append(path)
    return files


def main(argv: list[str]) -> int:
    secrets = needles()
    files = files_under(argv)
    leaking = []
    for path in files:
        try:
            data = path.read_bytes()
        except OSError:
            continue
        if scan_bytes(data, secrets):
            leaking.append(path)
    for path in leaking:
        print(f"ui_e2e_scan: secret found in {path}")
    if leaking:
        return 1
    print(
        f"ui_e2e_scan: no secret in {len(files)} file(s) ({len(secrets)} secret(s) of the run searched for)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
