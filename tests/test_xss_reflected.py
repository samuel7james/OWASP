import httpx

from owasp_inspector.core.http import AsyncHttpClient
from owasp_inspector.modules.xss.context import XssContext
from owasp_inspector.modules.xss.payloads import XssPayloadSet
from owasp_inspector.modules.xss.reflected import ReflectedXssScanner

_PAYLOADS = XssPayloadSet(
    xss_payloads=[('<script>alert("{c}")</script>', "script-tag")],
    dangerous_markers=["<script", "alert("],
)


def _make_ctx(handler):
    http = AsyncHttpClient(transport=httpx.MockTransport(handler), max_retries=0)
    return XssContext(http, _PAYLOADS)


async def test_flags_unescaped_reflection_in_script_body():
    def handler(request: httpx.Request) -> httpx.Response:
        query = httpx.QueryParams(request.url.query)
        q = query.get("q", "")
        return httpx.Response(200, text=f"<html><script>var search = '{q}';</script></html>")

    ctx = _make_ctx(handler)
    scanner = ReflectedXssScanner(ctx, max_concurrency=5)
    vulns = await scanner.scan(
        [("get", {"url": "https://example.com/search", "params": ["q"], "defaults": {"q": "hi"}})]
    )
    await ctx.http.aclose()

    assert len(vulns) == 1
    assert vulns[0]["status"] == "confirmed"
    assert vulns[0]["parameter"] == "q"


async def test_does_not_flag_properly_escaped_reflection():
    def handler(request: httpx.Request) -> httpx.Response:
        query = httpx.QueryParams(request.url.query)
        q = query.get("q", "")
        # simulate proper output encoding: server HTML-escapes before reflecting
        import html

        return httpx.Response(200, text=f"<html><body>results for: {html.escape(q)}</body></html>")

    ctx = _make_ctx(handler)
    scanner = ReflectedXssScanner(ctx, max_concurrency=5)
    vulns = await scanner.scan(
        [("get", {"url": "https://example.com/search", "params": ["q"], "defaults": {"q": "hi"}})]
    )
    await ctx.http.aclose()

    assert vulns == []


async def test_no_findings_when_canary_never_reflected():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html><body>static page, ignores all input</body></html>")

    ctx = _make_ctx(handler)
    scanner = ReflectedXssScanner(ctx, max_concurrency=5)
    vulns = await scanner.scan([("get", {"url": "https://example.com/page", "params": ["q"], "defaults": {"q": "hi"}})])
    await ctx.http.aclose()

    assert vulns == []


async def test_empty_targets_returns_no_findings():
    ctx = _make_ctx(lambda r: httpx.Response(200))
    scanner = ReflectedXssScanner(ctx, max_concurrency=5)
    vulns = await scanner.scan([])
    await ctx.http.aclose()
    assert vulns == []


async def test_context_aware_pass_confirms_event_handler_bypass():
    payloads = XssPayloadSet(
        xss_payloads=[],
        onclick_bypass_payloads=[("{c}alert(1)", "onclick-bypass-test")],
        dangerous_markers=["alert("],
    )

    def handler(request: httpx.Request) -> httpx.Response:
        query = httpx.QueryParams(request.url.query)
        q = query.get("q", "")
        return httpx.Response(200, text=f'<html><body><div onclick="{q}">click</div></body></html>')

    http = AsyncHttpClient(transport=httpx.MockTransport(handler), max_retries=0)
    ctx = XssContext(http, payloads)
    scanner = ReflectedXssScanner(ctx, max_concurrency=5)

    targets = [("get", {"url": "https://example.com/page", "params": ["q"], "defaults": {"q": "hi"}})]
    vulns = await scanner.scan_context_aware(targets, already_found=[])
    await http.aclose()

    assert len(vulns) == 1
    assert vulns[0]["confidence"] == "high"
    assert vulns[0]["status"] == "confirmed"


async def test_context_aware_pass_skips_params_already_found():
    already = [{"parameter": "q", "url": "https://example.com/page", "method": "get"}]

    async def handler(request):
        raise AssertionError("should not make any request — param already flagged")

    http = AsyncHttpClient(transport=httpx.MockTransport(lambda r: httpx.Response(200)), max_retries=0)
    ctx = XssContext(http, _PAYLOADS)
    scanner = ReflectedXssScanner(ctx, max_concurrency=5)

    targets = [("get", {"url": "https://example.com/page", "params": ["q"], "defaults": {"q": "hi"}})]
    vulns = await scanner.scan_context_aware(targets, already_found=already)
    await http.aclose()

    assert vulns == []
