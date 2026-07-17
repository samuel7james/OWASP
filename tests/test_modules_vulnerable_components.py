from owasp_inspector.core.models import ScanTarget
from owasp_inspector.core.module import ScanContext
from owasp_inspector.discovery.models import DiscoveryResult, Fingerprint
from owasp_inspector.modules.vulnerable_components import VulnerableComponentsModule


def _context(headers=None, fingerprint=None):
    discovery = DiscoveryResult(
        target_url="https://example.com/",
        final_url="https://example.com/",
        ok=True,
        headers=headers or {},
        fingerprint=fingerprint or Fingerprint(),
    )
    return ScanContext(target=ScanTarget(url="https://example.com/"), http=None, settings=None, discovery=discovery)


async def test_extracts_version_from_server_header():
    module = VulnerableComponentsModule()
    findings = await module.run(_context(headers={"Server": "Apache/2.4.29 (Ubuntu)"}))
    assert any("Apache 2.4.29" in f.title for f in findings)
    assert all(f.manual_verification_recommended for f in findings)


async def test_extracts_version_from_x_powered_by():
    module = VulnerableComponentsModule()
    findings = await module.run(_context(headers={"X-Powered-By": "PHP/7.2.24"}))
    assert any("PHP 7.2.24" in f.title for f in findings)


async def test_reports_fingerprint_when_known():
    module = VulnerableComponentsModule()
    findings = await module.run(
        _context(fingerprint=Fingerprint(technology="django", confidence="high", evidence=["Cookie match: csrftoken"]))
    )
    assert any("django" in f.title for f in findings)


async def test_no_findings_when_nothing_detected():
    module = VulnerableComponentsModule()
    findings = await module.run(_context())
    assert findings == []
