from _report_fixtures import make_finding, make_report

from owasp_inspector.reporting.serialize import report_to_dict


def test_report_to_dict_has_stable_top_level_schema():
    report = make_report([make_finding()])
    data = report_to_dict(report)

    for key in (
        "schema_version",
        "scan_id",
        "target_url",
        "final_url",
        "generated_at",
        "duration_seconds",
        "executive_summary",
        "risk",
        "discovery",
        "findings",
        "timeline",
    ):
        assert key in data


def test_finding_dict_shape():
    report = make_report([make_finding(parameter="id", evidence="e", remediation="r", references=["https://x"])])
    data = report_to_dict(report)
    finding = data["findings"][0]
    assert finding["severity"] == "medium"
    assert finding["confidence"] == "confirmed"
    assert finding["parameter"] == "id"
    assert finding["references"] == ["https://x"]


def test_discovery_dict_excludes_internal_robots_parser():
    report = make_report([])
    data = report_to_dict(report)
    assert "parser" not in data["discovery"]["robots"]
    assert data["discovery"]["robots"]["fetched"] is False


def test_report_to_dict_is_json_serializable():
    import json

    report = make_report([make_finding()])
    json.dumps(report_to_dict(report))  # must not raise
