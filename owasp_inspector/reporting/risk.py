from __future__ import annotations

from owasp_inspector.core.models import Confidence, Finding, Severity
from owasp_inspector.reporting.models import RiskScore

# Higher severity contributes more; confidence discounts the contribution so a
# pile of low-confidence heuristic candidates (IDOR/SSRF probes) can't push the
# score as hard as a small number of confirmed, high-severity findings.
_SEVERITY_WEIGHTS = {
    Severity.CRITICAL: 10,
    Severity.HIGH: 7,
    Severity.MEDIUM: 4,
    Severity.LOW: 2,
    Severity.INFO: 0,
}

_CONFIDENCE_MULTIPLIERS = {
    Confidence.CONFIRMED: 1.0,
    Confidence.HIGH: 0.8,
    Confidence.MEDIUM: 0.5,
    Confidence.LOW: 0.25,
}


def _grade_for(score: int) -> str:
    if score <= 0:
        return "A"
    if score <= 20:
        return "B"
    if score <= 45:
        return "C"
    if score <= 70:
        return "D"
    return "F"


def calculate_risk(findings: list[Finding]) -> RiskScore:
    severity_counts = {s.value: 0 for s in Severity}
    confirmed_count = 0
    manual_verification_count = 0
    raw = 0.0

    for finding in findings:
        severity_counts[finding.severity.value] += 1
        if finding.confidence == Confidence.CONFIRMED:
            confirmed_count += 1
        if finding.manual_verification_recommended:
            manual_verification_count += 1

        weight = _SEVERITY_WEIGHTS.get(finding.severity, 0)
        multiplier = _CONFIDENCE_MULTIPLIERS.get(finding.confidence, 0.25)
        raw += weight * multiplier

    # Score saturates rather than growing unbounded with finding count — a
    # couple of confirmed criticals should already read as "bad" without
    # needing dozens of findings to reach the ceiling.
    score = min(100, round(raw * 4))

    return RiskScore(
        score=score,
        grade=_grade_for(score),
        severity_counts=severity_counts,
        confirmed_count=confirmed_count,
        manual_verification_count=manual_verification_count,
    )
