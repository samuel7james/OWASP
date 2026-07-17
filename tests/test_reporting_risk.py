from owasp_inspector.core.models import Confidence, Finding, Severity
from owasp_inspector.reporting.risk import calculate_risk


def _finding(severity, confidence, manual_verify=False):
    return Finding(
        module="test",
        owasp_category="A00:Test",
        title="t",
        severity=severity,
        confidence=confidence,
        description="d",
        url="https://x",
        manual_verification_recommended=manual_verify,
    )


def test_no_findings_scores_zero_grade_a():
    risk = calculate_risk([])
    assert risk.score == 0
    assert risk.grade == "A"


def test_confirmed_critical_dominates_over_many_low_confidence_lows():
    critical = [_finding(Severity.CRITICAL, Confidence.CONFIRMED)]
    many_low = [_finding(Severity.LOW, Confidence.LOW, manual_verify=True) for _ in range(10)]

    critical_risk = calculate_risk(critical)
    low_risk = calculate_risk(many_low)

    assert critical_risk.score > low_risk.score


def test_severity_counts_and_confirmed_and_manual_verification_counts():
    findings = [
        _finding(Severity.HIGH, Confidence.CONFIRMED),
        _finding(Severity.LOW, Confidence.LOW, manual_verify=True),
        _finding(Severity.LOW, Confidence.LOW, manual_verify=True),
    ]
    risk = calculate_risk(findings)
    assert risk.severity_counts["high"] == 1
    assert risk.severity_counts["low"] == 2
    assert risk.confirmed_count == 1
    assert risk.manual_verification_count == 2


def test_score_saturates_at_100():
    findings = [_finding(Severity.CRITICAL, Confidence.CONFIRMED) for _ in range(20)]
    risk = calculate_risk(findings)
    assert risk.score == 100
    assert risk.grade == "F"


def test_grade_boundaries_are_monotonic():
    grades_seen = []
    for count in range(0, 12):
        findings = [_finding(Severity.MEDIUM, Confidence.CONFIRMED) for _ in range(count)]
        grades_seen.append(calculate_risk(findings).grade)
    order = {"A": 0, "B": 1, "C": 2, "D": 3, "F": 4}
    numeric = [order[g] for g in grades_seen]
    assert numeric == sorted(numeric)
