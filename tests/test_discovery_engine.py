import httpx

from owasp_inspector.core.http import AsyncHttpClient
from owasp_inspector.discovery.engine import run_discovery

ROBOTS_TXT = "User-agent: *\nDisallow: /admin/\n"
HOME_PAGE = """
<html><body>
    <a href="/search?q=test">search</a>
    <form action="/login" method="post"><input name="username"></form>
</body></html>
"""


def _handler(request):
    path = request.url.path
    if path == "/robots.txt":
        return httpx.Response(200, text=ROBOTS_TXT)
    if path == "/sitemap.xml":
        return httpx.Response(404)
    if path in ("/", "/search"):
        return httpx.Response(200, headers={"content-type": "text/html"}, text=HOME_PAGE if path == "/" else "<html></html>")
    return httpx.Response(404)


async def test_run_discovery_aggregates_everything():
    async with AsyncHttpClient(transport=httpx.MockTransport(_handler)) as http:
        result = await run_discovery(http, "http://example.com/", max_pages=10)

    assert result.ok is True
    assert result.robots.fetched is True
    assert result.tls.inspected is False  # http:// target, TLS skipped
    assert result.injectable_param_count > 0
    assert any(t.method == "post" and t.url.endswith("/login") for t in result.targets)


async def test_run_discovery_reports_failure_for_unreachable_target():
    def handler(request):
        raise httpx.ConnectError("refused", request=request)

    async with AsyncHttpClient(max_retries=0, transport=httpx.MockTransport(handler)) as http:
        result = await run_discovery(http, "http://example.com/", max_pages=10)

    assert result.ok is False
