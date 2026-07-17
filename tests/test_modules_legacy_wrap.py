from owasp_inspector.core.models import ScanTarget
from owasp_inspector.core.module import ScanContext
from owasp_inspector.modules import csrf as csrf_module

FAKE_RAW_FINDING = {"type": "SQL Injection (error-based)", "confidence": "high", "status": "confirmed", "parameter": "id", "url": "https://x/y?id=1"}


def _context(url="https://x/y"):
    return ScanContext(target=ScanTarget(url=url), http=None, settings=None)


async def test_csrf_module_bridges_sync_engine_and_converts_findings(monkeypatch):
    monkeypatch.setattr(csrf_module, "_run_sync", lambda url: [FAKE_RAW_FINDING])
    findings = await csrf_module.CsrfModule().run(_context())
    assert findings[0].module == "csrf"
    assert findings[0].owasp_category == "A01:2021-Broken Access Control"


async def test_no_findings_when_csrf_engine_returns_nothing(monkeypatch):
    monkeypatch.setattr(csrf_module, "_run_sync", lambda url: [])
    findings = await csrf_module.CsrfModule().run(_context())
    assert findings == []
