import httpx

from owasp_inspector.core.http import AsyncHttpClient
from owasp_inspector.core.models import ScanTarget
from owasp_inspector.core.module import ScanContext
from owasp_inspector.discovery.models import DiscoveryResult
from owasp_inspector.modules.idor import IdorModule


def _context(http, crawled_urls):
    discovery = DiscoveryResult(
        target_url="https://example.com/", final_url="https://example.com/", ok=True, crawled_urls=crawled_urls
    )
    return ScanContext(target=ScanTarget(url="https://example.com/"), http=http, settings=None, discovery=discovery)


async def test_flags_different_response_for_tampered_id():
    def handler(request):
        record_id = request.url.params.get("id")
        return httpx.Response(200, text=f"record for user {record_id}")

    async with AsyncHttpClient(transport=httpx.MockTransport(handler)) as http:
        module = IdorModule()
        findings = await module.run(_context(http, ["https://example.com/profile?id=5"]))

    assert len(findings) == 1
    assert findings[0].parameter == "id"
    assert findings[0].manual_verification_recommended is True


async def test_does_not_flag_identical_response():
    def handler(request):
        return httpx.Response(200, text="static content regardless of id")

    async with AsyncHttpClient(transport=httpx.MockTransport(handler)) as http:
        module = IdorModule()
        findings = await module.run(_context(http, ["https://example.com/profile?id=5"]))

    assert findings == []


async def test_ignores_non_numeric_and_non_id_params():
    def handler(request):
        return httpx.Response(200, text="ok")

    async with AsyncHttpClient(transport=httpx.MockTransport(handler)) as http:
        module = IdorModule()
        findings = await module.run(
            _context(http, ["https://example.com/search?q=hello", "https://example.com/user?id=abc"])
        )

    assert findings == []


async def test_no_findings_when_discovery_failed():
    async with AsyncHttpClient(transport=httpx.MockTransport(lambda r: httpx.Response(200))) as http:
        discovery = DiscoveryResult(target_url="https://x", final_url="https://x", ok=False)
        context = ScanContext(target=ScanTarget(url="https://x"), http=http, settings=None, discovery=discovery)
        assert await IdorModule().run(context) == []
