from owasp_inspector.core.models import ScanTarget
from owasp_inspector.core.module import ScanContext
from owasp_inspector.modules import csrf as csrf_module
from owasp_inspector.modules import sqli as sqli_module
from owasp_inspector.modules import xss as xss_module

FAKE_RAW_FINDING = {"type": "SQL Injection (error-based)", "confidence": "high", "status": "confirmed", "parameter": "id", "url": "https://x/y?id=1"}


def _context(url="https://x/y"):
    return ScanContext(target=ScanTarget(url=url), http=None, settings=None)


async def test_sqli_module_bridges_sync_engine_and_converts_findings(monkeypatch):
    monkeypatch.setattr(sqli_module, "_run_sync", lambda url: [FAKE_RAW_FINDING])
    findings = await sqli_module.SqliModule().run(_context())
    assert len(findings) == 1
    assert findings[0].module == "sqli"
    assert findings[0].owasp_category == "A03:2021-Injection"
    assert findings[0].parameter == "id"


async def test_xss_module_bridges_sync_engine_and_converts_findings(monkeypatch):
    monkeypatch.setattr(xss_module, "_run_sync", lambda url: [FAKE_RAW_FINDING])
    findings = await xss_module.XssModule().run(_context())
    assert findings[0].module == "xss"
    assert findings[0].owasp_category == "A03:2021-Injection"


async def test_csrf_module_bridges_sync_engine_and_converts_findings(monkeypatch):
    monkeypatch.setattr(csrf_module, "_run_sync", lambda url: [FAKE_RAW_FINDING])
    findings = await csrf_module.CsrfModule().run(_context())
    assert findings[0].module == "csrf"
    assert findings[0].owasp_category == "A01:2021-Broken Access Control"


async def test_no_findings_when_engine_returns_nothing(monkeypatch):
    monkeypatch.setattr(sqli_module, "_run_sync", lambda url: [])
    findings = await sqli_module.SqliModule().run(_context())
    assert findings == []
