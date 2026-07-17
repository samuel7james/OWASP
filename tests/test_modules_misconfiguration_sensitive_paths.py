import httpx

from owasp_inspector.core.http import AsyncHttpClient
from owasp_inspector.core.models import ScanTarget
from owasp_inspector.core.module import ScanContext
from owasp_inspector.discovery.models import DiscoveryResult, TlsInfo
from owasp_inspector.modules.misconfiguration import MisconfigurationModule

_ALL_SECURITY_HEADERS = {
    "strict-transport-security": "max-age=63072000",
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
    "content-security-policy": "default-src 'self'",
}


def _context(http, final_url="https://example.com/"):
    discovery = DiscoveryResult(
        target_url=final_url,
        final_url=final_url,
        ok=True,
        headers=_ALL_SECURITY_HEADERS,
        tls=TlsInfo(),
    )
    return ScanContext(target=ScanTarget(url=final_url), http=http, settings=None, discovery=discovery)


async def test_flags_exposed_git_head():
    def handler(request):
        path = request.url.path
        if path == "/.git/HEAD":
            return httpx.Response(200, text="ref: refs/heads/main\n")
        return httpx.Response(404)

    async with AsyncHttpClient(transport=httpx.MockTransport(handler)) as http:
        findings = await MisconfigurationModule().run(_context(http))
    assert any(".git" in f.title for f in findings)


async def test_flags_exposed_env_file():
    def handler(request):
        path = request.url.path
        if path == "/.env":
            return httpx.Response(200, text="DB_PASSWORD=hunter2\nDB_HOST=localhost\n")
        return httpx.Response(404)

    async with AsyncHttpClient(transport=httpx.MockTransport(handler)) as http:
        findings = await MisconfigurationModule().run(_context(http))
    assert any(".env" in f.title for f in findings)


async def test_soft_404_server_produces_no_sensitive_path_findings():
    def handler(request):
        return httpx.Response(200, text="<html>Not Found (but says 200)</html>")

    async with AsyncHttpClient(transport=httpx.MockTransport(handler)) as http:
        findings = await MisconfigurationModule().run(_context(http))
    # every path (including the random canary) returns 200, so nothing should be trusted
    assert findings == []


async def test_real_404_server_with_nothing_exposed_has_no_sensitive_path_findings():
    def handler(request):
        return httpx.Response(404)

    async with AsyncHttpClient(transport=httpx.MockTransport(handler)) as http:
        findings = await MisconfigurationModule().run(_context(http))
    assert findings == []


async def test_html_content_at_env_path_is_not_flagged():
    # A custom error page served at /.env with HTML content should not match
    # the .env signature (it isn't KEY=VALUE format and contains <html).
    def handler(request):
        if request.url.path == "/.env":
            return httpx.Response(200, text="<html><body>404 Not Found</body></html>")
        return httpx.Response(404)

    async with AsyncHttpClient(transport=httpx.MockTransport(handler)) as http:
        findings = await MisconfigurationModule().run(_context(http))
    assert findings == []
