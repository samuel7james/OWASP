from __future__ import annotations

from owasp_inspector.core.models import Confidence, Finding, Severity

_SEVERITY_BY_CONFIDENCE = {
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
}

_CONFIDENCE_BY_RAW = {
    "high": Confidence.HIGH,
    "medium": Confidence.MEDIUM,
    "low": Confidence.LOW,
}


def convert_legacy_finding(raw: dict, *, module: str, owasp_category: str, target_url: str) -> Finding:
    """Convert a raw finding dict — in the same `type`/`parameter`/`evidence`/
    `confidence`/`status`/`url`-or-`form_url` shape the legacy SQLi/XSS/CSRF
    engines used — into the new Finding model. `status` defaults to
    "candidate" when absent (the CSRF bypass tests never set it, only
    `confidence`), which correctly maps to `manual_verification_recommended`.
    """
    status = raw.get("status", "candidate")
    confidence_raw = raw.get("confidence", "medium")

    confidence = Confidence.CONFIRMED if status == "confirmed" else _CONFIDENCE_BY_RAW.get(confidence_raw, Confidence.LOW)
    severity = _SEVERITY_BY_CONFIDENCE.get(confidence_raw, Severity.MEDIUM)

    return Finding(
        module=module,
        owasp_category=owasp_category,
        title=raw.get("type") or "Unknown finding",
        severity=severity,
        confidence=confidence,
        description=raw.get("evidence") or raw.get("type") or "",
        url=raw.get("url") or raw.get("form_url") or target_url,
        parameter=raw.get("parameter"),
        evidence=raw.get("evidence"),
        manual_verification_recommended=status != "confirmed",
    )
