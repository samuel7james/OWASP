"""Shared test helpers for building fake scan results / reports (not a test module itself)."""

from owasp_inspector.core.lifecycle import Scan
from owasp_inspector.core.models import Confidence, Finding, Severity
from owasp_inspector.core.orchestrator import ScanResult
from owasp_inspector.discovery.models import DiscoveryResult, Fingerprint
from owasp_inspector.reporting.builder import build_report


def make_finding(title="Test finding", severity=Severity.MEDIUM, confidence=Confidence.CONFIRMED, **kwargs):
    return Finding(
        module=kwargs.pop("module", "test-module"),
        owasp_category=kwargs.pop("owasp_category", "A00:Test"),
        title=title,
        severity=severity,
        confidence=confidence,
        description=kwargs.pop("description", "a test finding"),
        url=kwargs.pop("url", "https://example.com/"),
        **kwargs,
    )


def make_scan_result(findings=None, *, url="https://example.com/", technology="unknown"):
    scan = Scan("test-scan-id", url)
    scan.start()
    scan.complete()
    discovery = DiscoveryResult(
        target_url=url,
        final_url=url,
        ok=True,
        status_code=200,
        headers={"server": "nginx"},
        fingerprint=Fingerprint(technology=technology),
    )
    return ScanResult(scan=scan, discovery=discovery, findings=findings or [])


def make_report(findings=None, **kwargs):
    return build_report(make_scan_result(findings, **kwargs))
