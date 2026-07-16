import httpx

from owasp_inspector.core.http import AsyncHttpClient
from owasp_inspector.discovery.target import normalize_url, probe_target


def test_normalize_url_adds_scheme_and_root_path():
    assert normalize_url("example.com") == "http://example.com/"


def test_normalize_url_preserves_path_and_query():
    assert normalize_url("http://example.com/a/b?x=1") == "http://example.com/a/b?x=1"


async def test_probe_returns_ok_on_success():
    def handler(request):
        return httpx.Response(200)

    async with AsyncHttpClient(transport=httpx.MockTransport(handler)) as http:
        result = await probe_target(http, "http://example.com/page")
        assert result.ok is True
        assert result.status_code == 200


async def test_probe_upgrades_http_to_https_on_failure():
    def handler(request):
        if request.url.scheme == "http":
            raise httpx.ConnectError("refused", request=request)
        return httpx.Response(200)

    async with AsyncHttpClient(max_retries=0, transport=httpx.MockTransport(handler)) as http:
        result = await probe_target(http, "http://example.com/page")
        assert result.ok is True
        assert result.final_url.startswith("https://")


async def test_probe_reports_failure_when_all_candidates_fail():
    def handler(request):
        raise httpx.ConnectError("refused", request=request)

    async with AsyncHttpClient(max_retries=0, transport=httpx.MockTransport(handler)) as http:
        result = await probe_target(http, "http://example.com/page")
        assert result.ok is False
        assert result.error is not None
