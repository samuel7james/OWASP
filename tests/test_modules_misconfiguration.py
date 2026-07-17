import httpx

from owasp_inspector.core.http import AsyncHttpClient
from owasp_inspector.core.models import ScanTarget
from owasp_inspector.core.module import ScanContext
from owasp_inspector.discovery.models import DiscoveryResult, TlsInfo
from owasp_inspector.modules.misconfiguration import MisconfigurationModule


def _context(headers, http, final_url="https://example.com/", tls=None):
    discovery = DiscoveryResult(
        target_url=final_url,
        final_url=final_url,
        ok=True,
        status_code=200,
        headers=headers,
        tls=tls or TlsInfo(),
    )
    return ScanContext(target=ScanTarget(url=final_url), http=http, settings=None, discovery=discovery)


async def test_flags_all_missing_security_headers():
    async with AsyncHttpClient(transport=httpx.MockTransport(lambda r: httpx.Response(404))) as http:
        findings = await MisconfigurationModule().run(_context({}, http))
    titles = {f.title for f in findings}
    assert "Missing HSTS header" in titles
    assert "Missing X-Frame-Options header" in titles
    assert "Missing Content-Security-Policy header" in titles


async def test_present_headers_are_not_flagged():
    headers = {
        "Strict-Transport-Security": "max-age=63072000",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Content-Security-Policy": "default-src 'self'",
    }
    async with AsyncHttpClient(transport=httpx.MockTransport(lambda r: httpx.Response(404))) as http:
        findings = await MisconfigurationModule().run(_context(headers, http))
    assert findings == []


async def test_hsts_not_required_over_plain_http():
    async with AsyncHttpClient(transport=httpx.MockTransport(lambda r: httpx.Response(404))) as http:
        findings = await MisconfigurationModule().run(_context({}, http, final_url="http://example.com/"))
    assert "Missing HSTS header" not in {f.title for f in findings}


async def test_unverifiable_tls_certificate_is_flagged():
    tls = TlsInfo(
        inspected=True,
        version="TLSv1.2",
        error="certificate not verifiable (self-signed, expired, or hostname mismatch)",
    )
    async with AsyncHttpClient(transport=httpx.MockTransport(lambda r: httpx.Response(404))) as http:
        findings = await MisconfigurationModule().run(_context({}, http, tls=tls))
    assert any(f.title == "TLS certificate not verifiable" for f in findings)


async def test_no_findings_when_discovery_failed():
    module = MisconfigurationModule()
    discovery = DiscoveryResult(target_url="https://x", final_url="https://x", ok=False)
    context = ScanContext(target=ScanTarget(url="https://x"), http=None, settings=None, discovery=discovery)
    assert await module.run(context) == []
