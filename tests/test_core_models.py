from owasp_inspector.core.models import Confidence, Finding, ScanTarget, Severity


def test_finding_requires_core_fields_and_defaults_are_sane():
    finding = Finding(
        module="test-module",
        owasp_category="A03:2021-Injection",
        title="Reflected XSS",
        severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED,
        description="param reflects unescaped",
        url="https://example.com/search?q=1",
    )
    assert finding.references == []
    assert finding.manual_verification_recommended is False
    assert finding.found_at is not None


def test_scan_target_defaults():
    target = ScanTarget(url="https://example.com")
    assert target.cookie is None
