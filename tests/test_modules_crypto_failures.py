from owasp_inspector.core.models import ScanTarget
from owasp_inspector.core.module import ScanContext
from owasp_inspector.discovery.models import CookieFlags, DiscoveryResult, ParamTarget, TlsInfo
from owasp_inspector.modules.crypto_failures import CryptoFailuresModule


def _context(**kwargs):
    defaults = dict(target_url="https://example.com/", final_url="https://example.com/", ok=True)
    defaults.update(kwargs)
    discovery = DiscoveryResult(**defaults)
    return ScanContext(target=ScanTarget(url=discovery.final_url), http=None, settings=None, discovery=discovery)


async def test_flags_cookie_missing_secure_over_https():
    findings = await CryptoFailuresModule().run(
        _context(cookie_flags=[CookieFlags(name="sid", secure=False, httponly=True, samesite="Lax")])
    )
    assert any("Secure flag" in f.title for f in findings)


async def test_does_not_flag_secure_cookie():
    findings = await CryptoFailuresModule().run(
        _context(cookie_flags=[CookieFlags(name="sid", secure=True, httponly=True, samesite="Lax")])
    )
    assert findings == []


async def test_flags_deprecated_tls_version():
    findings = await CryptoFailuresModule().run(_context(tls=TlsInfo(inspected=True, version="TLSv1.1")))
    assert any("TLSv1.1" in f.title for f in findings)


async def test_does_not_flag_modern_tls_version():
    findings = await CryptoFailuresModule().run(_context(tls=TlsInfo(inspected=True, version="TLSv1.3")))
    assert findings == []


async def test_flags_sensitive_param_in_url():
    findings = await CryptoFailuresModule().run(_context(crawled_urls=["https://example.com/reset?token=abc123"]))
    assert any(f.parameter == "token" for f in findings)
    assert all(f.manual_verification_recommended for f in findings if f.parameter == "token")


async def test_flags_mixed_content_form_action():
    findings = await CryptoFailuresModule().run(
        _context(targets=[ParamTarget(method="post", url="http://example.com/submit", params=["x"])])
    )
    assert any("plain HTTP" in f.title for f in findings)


async def test_no_findings_when_discovery_failed():
    discovery = DiscoveryResult(target_url="https://x", final_url="https://x", ok=False)
    context = ScanContext(target=ScanTarget(url="https://x"), http=None, settings=None, discovery=discovery)
    assert await CryptoFailuresModule().run(context) == []
