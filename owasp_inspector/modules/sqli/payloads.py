from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

# parents[3]: sqli/ -> modules/ -> owasp_inspector/ -> repo root. Reuses the
# existing corpus rather than duplicating it — same approach as
# discovery/fingerprint.py. A future packaged distribution will need this
# data shipped as package data; noted as a known limitation, not fixed here.
_DATA_DIR = Path(__file__).resolve().parents[3] / "Data" / "Payloads"
_PAYLOADS_FILE = _DATA_DIR / "sqli_payloads.json"
_PATTERNS_FILE = _DATA_DIR / "sqli_patterns.txt"


@dataclass
class SqliPayload:
    payload: str
    type: str
    group: str | None = None
    expected: str | None = None
    reflection: str | None = None
    columns: int | None = None


@dataclass
class SqliPayloadSet:
    payloads: list[SqliPayload] = field(default_factory=list)
    error_patterns: list[str] = field(default_factory=list)
    blind_fingerprint_probes: dict = field(default_factory=dict)


def _normalize(item: dict) -> SqliPayload:
    return SqliPayload(
        payload=item.get("payload", ""),
        type=item.get("type", ""),
        group=item.get("group"),
        expected=item.get("expected"),
        reflection=item.get("reflection"),
        columns=item.get("columns"),
    )


_cache: SqliPayloadSet | None = None


def load_sqli_payloads() -> SqliPayloadSet:
    global _cache
    if _cache is not None:
        return _cache

    payloads: list[SqliPayload] = []
    probes: dict = {}
    patterns: list[str] = []

    if _PAYLOADS_FILE.exists():
        try:
            data = json.loads(_PAYLOADS_FILE.read_text(encoding="utf-8"))
            payloads = [_normalize(p) for p in data.get("payloads", [])]
            probes = data.get("blind_fingerprint_probes", {})
        except (json.JSONDecodeError, OSError):
            pass

    if _PATTERNS_FILE.exists():
        try:
            patterns = [
                line.strip() for line in _PATTERNS_FILE.read_text(encoding="utf-8").splitlines() if line.strip()
            ]
        except OSError:
            pass

    _cache = SqliPayloadSet(payloads=payloads, error_patterns=patterns, blind_fingerprint_probes=probes)
    return _cache
