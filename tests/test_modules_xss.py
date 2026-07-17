import html

import httpx

import owasp_inspector.modules.xss as xss_module
from owasp_inspector.core.http import AsyncHttpClient
from owasp_inspector.core.models import ScanTarget
from owasp_inspector.core.module import ScanContext
from owasp_inspector.discovery.models import DiscoveryResult, ParamTarget
from owasp_inspector.modules.xss import XssModule, _param_targets


def test_param_targets_carries_defaults_through():
    discovery = DiscoveryResult(
        target_url="https://x/",
        final_url="https://x/",
        ok=True,
        targets=[ParamTarget(method="get", url="https://x/search", params=["q"], defaults={"q": "hi"})],
    )
    targets = _param_targets(discovery)
    assert targets == [("get", {"url": "https://x/search", "params": ["q"], "defaults": {"q": "hi"}})]


async def test_xss_module_finds_reflected_vuln_end_to_end(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        query = httpx.QueryParams(request.url.query)
        q = query.get("q", "")
        return httpx.Response(200, text=f"<html><script>var s = '{q}';</script></html>")

    def _fake_client(*, max_concurrency, timeout, max_retries):
        return AsyncHttpClient(
            max_concurrency=max_concurrency,
            max_retries=max_retries,
            timeout=5.0,
            transport=httpx.MockTransport(handler),
        )

    monkeypatch.setattr(xss_module, "AsyncHttpClient", _fake_client)

    discovery = DiscoveryResult(
        target_url="https://example.com/",
        final_url="https://example.com/",
        ok=True,
        targets=[ParamTarget(method="get", url="https://example.com/search", params=["q"], defaults={"q": "hi"})],
    )
    context = ScanContext(target=ScanTarget(url="https://example.com/"), http=None, settings=None, discovery=discovery)

    findings = await XssModule().run(context)

    assert any("XSS" in f.title for f in findings)
    assert all(f.module == "xss" for f in findings)
    assert all(f.owasp_category == "A03:2021-Injection" for f in findings)


async def test_xss_module_no_false_positive_on_properly_escaped_target(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        query = httpx.QueryParams(request.url.query)
        q = query.get("q", "")
        return httpx.Response(200, text=f"<html><body>results for: {html.escape(q)}</body></html>")

    def _fake_client(*, max_concurrency, timeout, max_retries):
        return AsyncHttpClient(
            max_concurrency=max_concurrency,
            max_retries=max_retries,
            timeout=5.0,
            transport=httpx.MockTransport(handler),
        )

    monkeypatch.setattr(xss_module, "AsyncHttpClient", _fake_client)

    discovery = DiscoveryResult(
        target_url="https://example.com/",
        final_url="https://example.com/",
        ok=True,
        targets=[ParamTarget(method="get", url="https://example.com/search", params=["q"], defaults={"q": "hi"})],
    )
    context = ScanContext(target=ScanTarget(url="https://example.com/"), http=None, settings=None, discovery=discovery)

    findings = await XssModule().run(context)

    assert findings == []


async def test_xss_module_returns_empty_when_discovery_failed():
    discovery = DiscoveryResult(target_url="https://x/", final_url="https://x/", ok=False)
    context = ScanContext(target=ScanTarget(url="https://x/"), http=None, settings=None, discovery=discovery)
    assert await XssModule().run(context) == []


async def test_xss_module_returns_empty_when_no_targets():
    discovery = DiscoveryResult(target_url="https://x/", final_url="https://x/", ok=True)
    context = ScanContext(target=ScanTarget(url="https://x/"), http=None, settings=None, discovery=discovery)
    assert await XssModule().run(context) == []
