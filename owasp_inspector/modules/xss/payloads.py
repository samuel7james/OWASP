from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

# parents[3]: xss/ -> modules/ -> owasp_inspector/ -> repo root. Reuses the
# existing corpus rather than duplicating it — same approach as sqli/payloads.py.
_PAYLOADS_FILE = Path(__file__).resolve().parents[3] / "Data" / "Payloads" / "xsstrike_payloads.json"

PayloadPair = tuple[str, str]  # (payload_template, type_label)


def _as_text(value) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, (list, tuple)):
        for item in value:
            if isinstance(item, str) and item:
                return item
        return ""
    if value is None:
        return ""
    return str(value)


def _normalize_pairs(values, default_label: str) -> list[PayloadPair]:
    out = []
    for value in values or []:
        if isinstance(value, (list, tuple)):
            payload = _as_text(value[0] if len(value) > 0 else "")
            label = _as_text(value[1] if len(value) > 1 else default_label) or default_label
        else:
            payload = _as_text(value)
            label = default_label
        if payload:
            out.append((payload, label))
    return out


@dataclass
class XssPayloadSet:
    xss_payloads: list[PayloadPair] = field(default_factory=list)
    js_context_payloads: list[PayloadPair] = field(default_factory=list)
    onclick_bypass_payloads: list[PayloadPair] = field(default_factory=list)
    attribute_escape_payloads: list[PayloadPair] = field(default_factory=list)
    dangerous_markers: list[str] = field(default_factory=list)


_cache: XssPayloadSet | None = None


def load_xss_payloads() -> XssPayloadSet:
    global _cache
    if _cache is not None:
        return _cache

    data = {}
    if _PAYLOADS_FILE.exists():
        try:
            data = json.loads(_PAYLOADS_FILE.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            data = {}

    xss_payloads = _normalize_pairs(data.get("XSS_PAYLOADS", []), "xss")
    # Same two payloads the legacy PayloadManager guarantees are always present
    # regardless of what's in the corpus file (used to confirm stored-DOM
    # angle-bracket-encoding bypasses) — kept here for parity, harmless for
    # reflected-only scanning since they're just two more payload variants.
    for payload, label in (
        ('<><img src=1 onerror=alert("{c}")>', "stored-dom-angle-bypass"),
        ('<><svg onload=alert("{c}")>', "stored-dom-svg-bypass"),
    ):
        if payload not in {p for p, _ in xss_payloads}:
            xss_payloads.append((payload, label))

    _cache = XssPayloadSet(
        xss_payloads=xss_payloads,
        js_context_payloads=_normalize_pairs(data.get("JS_CONTEXT_PAYLOADS", []), "js-context"),
        onclick_bypass_payloads=_normalize_pairs(data.get("ONCLICK_BYPASS_PAYLOADS", []), "onclick-bypass"),
        attribute_escape_payloads=_normalize_pairs(data.get("ATTRIBUTE_ESCAPE_PAYLOADS", []), "attr-escape"),
        dangerous_markers=data.get("DANGEROUS_MARKERS", []),
    )
    return _cache
