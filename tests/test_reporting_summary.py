from _report_fixtures import make_finding, make_report

from owasp_inspector.core.models import Confidence


def test_summary_for_zero_findings_is_reassuring_but_not_a_guarantee():
    report = make_report([])
    assert "No findings" in report.executive_summary
    assert "does not guarantee" in report.executive_summary


def test_summary_mentions_counts_grade_and_confirmed_vs_manual():
    report = make_report([
        make_finding(),
        make_finding(confidence=Confidence.LOW, manual_verification_recommended=True),
    ])
    assert report.risk.grade in report.executive_summary
    assert "1 finding(s) are confirmed" in report.executive_summary
    assert "1 require manual verification" in report.executive_summary
