import httpx

from owasp_inspector.core.http import AsyncHttpClient
from owasp_inspector.core.models import ScanTarget
from owasp_inspector.core.module import ScanContext
from owasp_inspector.discovery.models import DiscoveryResult
from owasp_inspector.modules.insecure_design import InsecureDesignModule


def _context(http, crawled_urls=None):
    discovery = DiscoveryResult(
        target_url="https://example.com/", final_url="https://example.com/", ok=True,
        crawled_urls=crawled_urls or [],
    )
    return ScanContext(target=ScanTarget(url="https://example.com/"), http=http, settings=None, discovery=discovery)


async def test_flags_django_debug_page():
    def handler(request):
        return httpx.Response(500, text="Technical 500 Error <p>Exception Type: ValueError</p> django.core.handlers.wsgi")

    async with AsyncHttpClient(transport=httpx.MockTransport(handler)) as http:
        findings = await InsecureDesignModule().run(_context(http))
    assert any("Django" in f.title for f in findings)


async def test_flags_werkzeug_debugger():
    def handler(request):
        return httpx.Response(500, text="Werkzeug Debugger — The debugger caught an exception")

    async with AsyncHttpClient(transport=httpx.MockTransport(handler)) as http:
        findings = await InsecureDesignModule().run(_context(http))
    assert any("Werkzeug" in f.title for f in findings)


async def test_no_findings_on_clean_page():
    def handler(request):
        return httpx.Response(200, text="<html><body>Welcome</body></html>")

    async with AsyncHttpClient(transport=httpx.MockTransport(handler)) as http:
        findings = await InsecureDesignModule().run(_context(http))
    assert findings == []


async def test_deduplicates_same_signature_across_pages():
    def handler(request):
        return httpx.Response(500, text="Fatal error: <b>Warning</b>: on line <b>42</b>")

    async with AsyncHttpClient(transport=httpx.MockTransport(handler)) as http:
        findings = await InsecureDesignModule().run(
            _context(http, crawled_urls=["https://example.com/a", "https://example.com/b"])
        )
    php_findings = [f for f in findings if "PHP" in f.title]
    assert len(php_findings) == 1


async def test_no_findings_when_discovery_failed():
    async with AsyncHttpClient(transport=httpx.MockTransport(lambda r: httpx.Response(200))) as http:
        discovery = DiscoveryResult(target_url="https://x", final_url="https://x", ok=False)
        context = ScanContext(target=ScanTarget(url="https://x"), http=http, settings=None, discovery=discovery)
        assert await InsecureDesignModule().run(context) == []
