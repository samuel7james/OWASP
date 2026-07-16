import httpx

from owasp_inspector.core.http import AsyncHttpClient
from owasp_inspector.core.models import ScanTarget
from owasp_inspector.core.module import ScanContext
from owasp_inspector.discovery.models import DiscoveryResult
from owasp_inspector.modules.software_integrity import SoftwareIntegrityModule


def _context(http):
    discovery = DiscoveryResult(target_url="https://example.com/", final_url="https://example.com/", ok=True)
    return ScanContext(target=ScanTarget(url="https://example.com/"), http=http, settings=None, discovery=discovery)


async def test_flags_cross_origin_script_without_sri():
    page = '<html><body><script src="https://cdn.other.com/lib.js"></script></body></html>'

    def handler(request):
        if str(request.url) == "https://example.com/":
            return httpx.Response(200, text=page)
        return httpx.Response(404)

    async with AsyncHttpClient(transport=httpx.MockTransport(handler)) as http:
        findings = await SoftwareIntegrityModule().run(_context(http))
    assert any("Subresource Integrity" in f.title for f in findings)


async def test_does_not_flag_cross_origin_script_with_sri():
    page = (
        '<html><body><script src="https://cdn.other.com/lib.js" '
        'integrity="sha384-abc" crossorigin="anonymous"></script></body></html>'
    )

    def handler(request):
        if str(request.url) == "https://example.com/":
            return httpx.Response(200, text=page)
        return httpx.Response(404)

    async with AsyncHttpClient(transport=httpx.MockTransport(handler)) as http:
        findings = await SoftwareIntegrityModule().run(_context(http))
    assert findings == []


async def test_does_not_flag_same_origin_script():
    page = '<html><body><script src="/static/app.js"></script></body></html>'

    def handler(request):
        if str(request.url) == "https://example.com/":
            return httpx.Response(200, text=page)
        return httpx.Response(404)

    async with AsyncHttpClient(transport=httpx.MockTransport(handler)) as http:
        findings = await SoftwareIntegrityModule().run(_context(http))
    assert findings == []


async def test_flags_exposed_source_map():
    page = '<html><body><script src="https://cdn.other.com/lib.js"></script></body></html>'

    def handler(request):
        url = str(request.url)
        if url == "https://example.com/":
            return httpx.Response(200, text=page)
        if url == "https://cdn.other.com/lib.js.map":
            return httpx.Response(200, text='{"version":3,"sourcesContent":["console.log(1)"]}')
        return httpx.Response(404)

    async with AsyncHttpClient(transport=httpx.MockTransport(handler)) as http:
        findings = await SoftwareIntegrityModule().run(_context(http))
    assert any("source map" in f.title for f in findings)


async def test_no_findings_when_discovery_failed():
    async with AsyncHttpClient(transport=httpx.MockTransport(lambda r: httpx.Response(200))) as http:
        discovery = DiscoveryResult(target_url="https://x", final_url="https://x", ok=False)
        context = ScanContext(target=ScanTarget(url="https://x"), http=http, settings=None, discovery=discovery)
        assert await SoftwareIntegrityModule().run(context) == []
