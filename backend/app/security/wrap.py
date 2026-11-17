"""Nonce generation and untrusted-content wrapping/stripping, ported from the legacy builder."""

from __future__ import annotations

import html
import secrets
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass

# context pack §7.1 — the five reasons[].source values plus the verifier's one block (P3-T09),
# the three of the learned-knowledge section (DEC-210): an approved entry, the rationale of a
# past decision, an analyst's note — all three are text a person wrote, so all three are untrusted —
# and S2's `siem_context`: SOAR's `enrichment` object, one untrusted block of the ① prompt.
# DEC-223 adds `mitre_reference`: MITRE's own text for the alert's technique ids, read from the local ATT&CK
# extract. It is a block (the linter accepts no prose outside one) but it is not a `reasons[].source`: the
# output schemas and `output_guard.REASON_SOURCES` do not list it, so a reason cannot cite it.
BLOCK_SOURCES = frozenset(
    {
        "wazuh_raw_log",
        "rule_description",
        "correlation_samples",
        "kb_playbook",
        "context",
        "siem_context",
        "proposer",
        "kb_learned",
        "decision_history",
        "analyst_note",
        "mitre_reference",
    }
)
#: The block sources whose text is ours, from a file shipped with the product, not data from an alert or text a
#: person wrote (DEC-223, spec 5): the injection detector is not run over them. A source is listed here only if
#: no alert, SIEM, analyst or model text can reach it. The set is a subset of `BLOCK_SOURCES` (a test pins it).
REFERENCE_SOURCES = frozenset({"mitre_reference"})
TRUNCATION_MARKER = "[truncated]"
NONCE_REMOVED = "[nonce-removed]"


@dataclass(frozen=True)
class Block:
    source: str
    attrs: Mapping[str, str]
    plain: str
    escaped: str
    truncated: bool
    dropped_bytes: int
    rendered: str


def new_nonce() -> str:
    """One nonce per build — keyword-only and required everywhere it is used
    (design note 5): a forgotten argument must be a `TypeError`, not silence."""
    return secrets.token_hex(8)


def normalise(text: str) -> str:
    """NFKC-fold compatibility look-alikes (e.g. fullwidth `＜` U+FF1C → `<`)
    before escaping, so escaping catches them."""
    return unicodedata.normalize("NFKC", text)


def strip_nonce(text: str, nonce: str) -> str:
    """Remove `nonce` from already-normalised `text` so a leaked nonce cannot be
    replayed to forge an authoritative boundary."""
    return text.replace(nonce, NONCE_REMOVED)


def _dropped_bytes(text: str, limit_bytes: int) -> int:
    encoded = text.encode("utf-8")
    if len(encoded) <= limit_bytes:
        return 0
    head = encoded[:limit_bytes].decode("utf-8", errors="ignore")
    return len(encoded) - len(head.encode("utf-8"))


def truncate_block(text: str, limit_bytes: int) -> tuple[str, bool]:
    """Cut `text` to a UTF-8 byte budget without splitting a multibyte character.
    The marker is appended to the returned text itself (inside the block), never
    returned as a separate value — that is what let the legacy `boc_raw_log`
    attach the marker outside the wrapped content (§7.4)."""
    dropped = _dropped_bytes(text, limit_bytes)
    if dropped == 0:
        return text, False
    encoded = text.encode("utf-8")
    head = encoded[:limit_bytes].decode("utf-8", errors="ignore")
    return f"{head}\n{TRUNCATION_MARKER} {dropped} bytes dropped", True


def untrusted_block(
    text: str,
    source: str,
    *,
    nonce: str,
    limit_bytes: int | None = None,
    **attrs: str,
) -> Block:
    """The only function that emits an `<untrusted_data …>` boundary. Order:
    normalise → strip the nonce → truncate (if bounded) → escape → render —
    see design note 2 for why each step must precede the next."""
    if source not in BLOCK_SOURCES:
        raise ValueError(
            f"untrusted_block: unknown source {source!r}, must be one of {sorted(BLOCK_SOURCES)}"
        )

    stripped = strip_nonce(normalise(text), nonce)
    if limit_bytes is None:
        plain, truncated, dropped_bytes = stripped, False, 0
    else:
        plain, truncated = truncate_block(stripped, limit_bytes)
        dropped_bytes = _dropped_bytes(stripped, limit_bytes)

    escaped = html.escape(plain, quote=False)
    attrs_str = "".join(
        f' {key}="{html.escape(str(value), quote=True)}"' for key, value in sorted(attrs.items())
    )
    rendered = (
        f'<untrusted_data nonce="{nonce}" source="{source}"{attrs_str}>\n'
        f"{escaped}\n"
        f'</untrusted_data nonce="{nonce}">'
    )
    return Block(
        source=source,
        attrs=dict(attrs),
        plain=plain,
        escaped=escaped,
        truncated=truncated,
        dropped_bytes=dropped_bytes,
        rendered=rendered,
    )
