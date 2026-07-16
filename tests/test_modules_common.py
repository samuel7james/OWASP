from owasp_inspector.core.models import Confidence, Severity
from owasp_inspector.modules._legacy_common import convert_legacy_finding


def test_confirmed_status_maps_to_confirmed_confidence_and_no_manual_flag():
    raw = {"type": "SQL Injection", "confidence": "high", "status": "confirmed", "url": "https://x/y?id=1", "parameter": "id"}
    finding = convert_legacy_finding(raw, module="sqli", owasp_category="A03:2021-Injection", target_url="https://x/y")
    assert finding.confidence == Confidence.CONFIRMED
    assert finding.severity == Severity.HIGH
    assert finding.manual_verification_recommended is False
    assert finding.parameter == "id"


def test_candidate_status_recommends_manual_verification():
    raw = {"type": "XSS (Reflected)", "confidence": "low", "status": "candidate", "url": "https://x/y"}
    finding = convert_legacy_finding(raw, module="xss", owasp_category="A03:2021-Injection", target_url="https://x/y")
    assert finding.confidence == Confidence.LOW
    assert finding.manual_verification_recommended is True


def test_falls_back_to_form_url_and_target_url():
    raw = {"type": "CSRF (missing token)", "confidence": "medium", "status": "suspected", "form_url": "https://x/form"}
    finding = convert_legacy_finding(raw, module="csrf", owasp_category="A01:2021-Broken Access Control", target_url="https://x/")
    assert finding.url == "https://x/form"

    raw_no_url = {"type": "CSRF", "confidence": "medium", "status": "suspected"}
    finding2 = convert_legacy_finding(raw_no_url, module="csrf", owasp_category="A01:2021-Broken Access Control", target_url="https://x/")
    assert finding2.url == "https://x/"
