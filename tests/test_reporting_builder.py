from _report_fixtures import make_finding, make_scan_result

from owasp_inspector.reporting.builder import build_report


def test_build_report_carries_scan_and_discovery_identity():
    scan_result = make_scan_result([make_finding()], url="https://target.example/")
    report = build_report(scan_result)

    assert report.scan_id == scan_result.scan.scan_id
    assert report.final_url == "https://target.example/"
    assert report.findings == scan_result.findings
    assert report.duration_seconds is not None


def test_build_report_timeline_reflects_scan_history():
    scan_result = make_scan_result([])
    report = build_report(scan_result)
    states = [event["state"] for event in report.timeline]
    assert states == ["queued", "running", "done"]


def test_build_report_computes_executive_summary_and_risk():
    scan_result = make_scan_result([make_finding()])
    report = build_report(scan_result)
    assert report.executive_summary  # non-empty
    assert report.risk.score >= 0
