import httpx

import owasp_inspector.modules.sqli as sqli_module
from owasp_inspector.core.http import AsyncHttpClient
from owasp_inspector.core.models import ScanTarget
from owasp_inspector.core.module import ScanContext
from owasp_inspector.discovery.models import DiscoveryResult, ParamTarget
from owasp_inspector.modules.sqli import SqliModule, _cookie_targets, _param_targets

_SQL_ERROR_BODY = "Warning: mysql_fetch_array(): supplied argument is not a valid MySQL result resource"


def test_param_targets_carries_defaults_through():
    discovery = DiscoveryResult(
        target_url="https://x/", final_url="https://x/", ok=True,
        targets=[ParamTarget(method="get", url="https://x/item", params=["id"], defaults={"id": "1"})],
    )
    targets = _param_targets(discovery)
    assert targets == [("get", {"url": "https://x/item", "params": ["id"], "defaults": {"id": "1"}})]


def test_cookie_targets_excludes_denylisted_and_empty():
    discovery = DiscoveryResult(
        target_url="https://x/", final_url="https://x/", ok=True,
        cookies={"PHPSESSID": "abc", "TrackingId": "xyz123", "_ga": "should-be-excluded"},
    )
    targets = _cookie_targets(discovery, probe_all=False)
    names = {t[1]["params"][0] for t in targets}
    assert "TrackingId" in names
    assert "PHPSESSID" not in names  # denylisted (session cookie)
    assert "_ga" not in names  # denylisted (tracking cookie)


def test_cookie_targets_probe_all_bypasses_denylist():
    discovery = DiscoveryResult(target_url="https://x/", final_url="https://x/", ok=True, cookies={"_ga": "value"})
    targets = _cookie_targets(discovery, probe_all=True)
    assert any(t[1]["params"][0] == "_ga" for t in targets)


async def test_sqli_module_finds_error_based_vuln_end_to_end(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        query = httpx.QueryParams(request.url.query)
        if "'" in query.get("id", ""):
            return httpx.Response(200, text=_SQL_ERROR_BODY)
        return httpx.Response(200, text="<html>Item</html>")

    def _fake_client(*, max_concurrency, timeout, max_retries):
        return AsyncHttpClient(
            max_concurrency=max_concurrency, max_retries=max_retries, timeout=5.0,
            transport=httpx.MockTransport(handler),
        )

    monkeypatch.setattr(sqli_module, "AsyncHttpClient", _fake_client)

    discovery = DiscoveryResult(
        target_url="https://example.com/", final_url="https://example.com/", ok=True,
        targets=[ParamTarget(method="get", url="https://example.com/item", params=["id"], defaults={"id": "1"})],
    )
    context = ScanContext(target=ScanTarget(url="https://example.com/"), http=None, settings=None, discovery=discovery)

    findings = await SqliModule().run(context)

    assert any("Error Pattern Match" in f.title for f in findings)
    assert all(f.module == "sqli" for f in findings)
    assert all(f.owasp_category == "A03:2021-Injection" for f in findings)


async def test_sqli_module_returns_empty_when_discovery_failed():
    discovery = DiscoveryResult(target_url="https://x/", final_url="https://x/", ok=False)
    context = ScanContext(target=ScanTarget(url="https://x/"), http=None, settings=None, discovery=discovery)
    assert await SqliModule().run(context) == []


async def test_sqli_module_returns_empty_when_no_targets():
    discovery = DiscoveryResult(target_url="https://x/", final_url="https://x/", ok=True)
    context = ScanContext(target=ScanTarget(url="https://x/"), http=None, settings=None, discovery=discovery)
    assert await SqliModule().run(context) == []
