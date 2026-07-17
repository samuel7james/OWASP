import httpx

from owasp_inspector.core.http import AsyncHttpClient
from owasp_inspector.core.models import ScanTarget
from owasp_inspector.core.module import ScanContext
from owasp_inspector.discovery.models import DiscoveryResult, ParamTarget
from owasp_inspector.modules.ssrf import SsrfModule


def _context(http, targets):
    discovery = DiscoveryResult(
        target_url="https://example.com/", final_url="https://example.com/", ok=True, targets=targets
    )
    return ScanContext(target=ScanTarget(url="https://example.com/"), http=http, settings=None, discovery=discovery)


async def test_flags_metadata_leak_on_ssrf_suggestive_param():
    def handler(request):
        if "169.254.169.254" in str(request.url):
            return httpx.Response(200, text="ami-id: ami-0123456789")
        return httpx.Response(200, text="normal page")

    targets = [ParamTarget(method="get", url="https://example.com/fetch", params=["callback_url"])]
    async with AsyncHttpClient(transport=httpx.MockTransport(handler)) as http:
        findings = await SsrfModule().run(_context(http, targets))

    assert len(findings) >= 1
    assert findings[0].parameter == "callback_url"
    assert findings[0].manual_verification_recommended is True


async def test_ignores_params_without_ssrf_suggestive_names():
    def handler(request):
        return httpx.Response(200, text="ami-id: leak-that-should-never-be-checked")

    targets = [ParamTarget(method="get", url="https://example.com/page", params=["username"])]
    async with AsyncHttpClient(transport=httpx.MockTransport(handler)) as http:
        findings = await SsrfModule().run(_context(http, targets))

    assert findings == []


async def test_no_findings_when_response_is_unremarkable():
    def handler(request):
        return httpx.Response(200, text="just a normal page")

    targets = [ParamTarget(method="get", url="https://example.com/fetch", params=["redirect_url"])]
    async with AsyncHttpClient(transport=httpx.MockTransport(handler)) as http:
        findings = await SsrfModule().run(_context(http, targets))

    assert findings == []


async def test_no_findings_when_discovery_failed():
    async with AsyncHttpClient(transport=httpx.MockTransport(lambda r: httpx.Response(200))) as http:
        discovery = DiscoveryResult(target_url="https://x", final_url="https://x", ok=False)
        context = ScanContext(target=ScanTarget(url="https://x"), http=http, settings=None, discovery=discovery)
        assert await SsrfModule().run(context) == []
