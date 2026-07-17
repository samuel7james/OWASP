from __future__ import annotations

import json
import re
from pathlib import Path

from owasp_inspector.core.http import AsyncHttpClient
from owasp_inspector.discovery.models import Fingerprint

# Reuses the existing signature corpus (Data/Payloads/csrf_payloads/framework_signatures.json)
# rather than duplicating it — it's just data, so no coupling to the legacy Logic/ code.
# parents[2]: discovery/ -> owasp_inspector/ -> repo root. Holds for an editable/source
# checkout; a future packaged distribution will need this data shipped as package data.
_SIGNATURES_FILE = (
    Path(__file__).resolve().parents[2] / "Data" / "Payloads" / "csrf_payloads" / "framework_signatures.json"
)

_signatures_cache: dict | None = None


def _load_signatures() -> dict:
    global _signatures_cache
    if _signatures_cache is not None:
        return _signatures_cache
    if not _SIGNATURES_FILE.exists():
        _signatures_cache = {}
        return _signatures_cache
    try:
        with open(_SIGNATURES_FILE, encoding="utf-8") as f:
            _signatures_cache = json.load(f).get("frameworks", {})
    except (json.JSONDecodeError, OSError):
        _signatures_cache = {}
    return _signatures_cache


def _pattern_matches(pattern: str, value: str) -> bool:
    if not pattern:
        return True
    try:
        return re.search(pattern, value, re.IGNORECASE) is not None
    except re.error:
        return pattern.lower() in value.lower()


async def fingerprint_target(http: AsyncHttpClient, url: str) -> Fingerprint:
    signatures = _load_signatures()
    if not signatures:
        return Fingerprint()

    response = await http.get(url)
    if response is None:
        return Fingerprint()

    headers = {k.lower(): v for k, v in response.headers.items()}
    cookies = dict(response.cookies)
    html = response.text

    scores: dict[str, int] = {}
    evidence: dict[str, list[str]] = {}

    for tech, sigs in signatures.items():
        score = 0
        found: list[str] = []

        for h in sigs.get("headers", []):
            name = h.get("name", "").lower()
            pattern = h.get("pattern", "")
            if name in headers and _pattern_matches(pattern, headers[name]):
                score += 1
                found.append(f"Header match: {name}")

        for c in sigs.get("cookies", []):
            name = c.get("name", "")
            if any(name.lower() == k.lower() for k in cookies):
                score += 1
                found.append(f"Cookie match: {name}")

        for hp in sigs.get("html_patterns", []):
            if _pattern_matches(hp, html):
                score += 1
                found.append(f"HTML pattern match: {hp}")

        scores[tech] = score
        evidence[tech] = found

    best_tech = max(scores, key=scores.get, default="unknown")
    best_score = scores.get(best_tech, 0)

    if best_score <= 0:
        return Fingerprint()

    confidence = "low"
    if best_score >= 3:
        confidence = "high"
    elif best_score == 2:
        confidence = "medium"

    return Fingerprint(technology=best_tech, confidence=confidence, evidence=evidence[best_tech])
