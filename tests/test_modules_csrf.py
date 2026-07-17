import httpx

import owasp_inspector.modules.csrf as csrf_module
from owasp_inspector.core.http import AsyncHttpClient
from owasp_inspector.core.models import ScanTarget
from owasp_inspector.core.module import ScanContext
from owasp_inspector.discovery.models import DiscoveryResult, ParamTarget
from owasp_inspector.modules.csrf import CsrfModule, _build_forms


def test_build_forms_detects_token_field_and_dedupes():
    discovery = DiscoveryResult(
        target_url="https://x/", final_url="https://x/", ok=True,
        targets=[
            ParamTarget(method="post", url="https://x/settings", params=["email", "csrf_token"], defaults={"email": "a@x.com", "csrf_token": "tok"}),
            ParamTarget(method="post", url="https://x/settings", params=["csrf_token", "email"], defaults={"email": "a@x.com", "csrf_token": "tok"}),
            ParamTarget(method="get", url="https://x/search", params=["q"], defaults={}),
        ],
    )
    forms = _build_forms(discovery)
    assert len(forms) == 1
    assert forms[0]["has_token"] is True
    assert forms[0]["token_field"] == "csrf_token"


def test_build_forms_includes_get_method_form_but_not_bare_get_link():
    # Regression: DVWA's own CSRF lab uses <form method="GET"> for its
    # password-change action — excluding GET entirely would mean this
    # module finds zero targets against a canonical real-world CSRF page.
    # A bare crawled link with a query string must still be excluded: it's
    # not a form, and there's no reason to believe it's state-changing.
    discovery = DiscoveryResult(
        target_url="https://x/", final_url="https://x/", ok=True,
        targets=[
            ParamTarget(method="get", url="https://x/csrf", params=["password_new"], defaults={"password_new": ""}, is_form=True),
            ParamTarget(method="get", url="https://x/page", params=["id"], defaults={"id": "1"}, is_form=False),
        ],
    )
    forms = _build_forms(discovery)
    assert len(forms) == 1
    assert forms[0]["url"] == "https://x/csrf"
    assert forms[0]["method"] == "GET"


async def test_csrf_module_finds_no_token_defense_on_get_method_form(monkeypatch):
    # The attack request must go out as GET (matching the form's own
    # method), not POST — DVWA's CSRF page only reads $_GET for this action.
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and "password_new" in str(request.url):
            return httpx.Response(200, text="Password Changed.")
        return httpx.Response(200, text="<form method='GET'></form>")

    def _fake_client(*, max_concurrency, timeout, max_retries):
        return AsyncHttpClient(
            max_concurrency=max_concurrency, max_retries=max_retries, timeout=5.0,
            transport=httpx.MockTransport(handler),
        )

    monkeypatch.setattr(csrf_module, "AsyncHttpClient", _fake_client)

    discovery = DiscoveryResult(
        target_url="https://example.com/", final_url="https://example.com/", ok=True,
        targets=[ParamTarget(method="get", url="https://example.com/csrf", params=["password_new"], defaults={"password_new": ""}, is_form=True)],
    )
    context = ScanContext(target=ScanTarget(url="https://example.com/"), http=None, settings=None, discovery=discovery)

    findings = await CsrfModule().run(context)
    assert any("CSRF" in f.title for f in findings)


async def test_csrf_module_finds_no_token_defense_end_to_end(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return httpx.Response(200, text="Your profile updated")
        return httpx.Response(200, text="<form></form>")

    def _fake_client(*, max_concurrency, timeout, max_retries):
        return AsyncHttpClient(
            max_concurrency=max_concurrency, max_retries=max_retries, timeout=5.0,
            transport=httpx.MockTransport(handler),
        )

    monkeypatch.setattr(csrf_module, "AsyncHttpClient", _fake_client)

    discovery = DiscoveryResult(
        target_url="https://example.com/", final_url="https://example.com/", ok=True,
        targets=[ParamTarget(method="post", url="https://example.com/change-email", params=["email"], defaults={"email": ""})],
    )
    context = ScanContext(target=ScanTarget(url="https://example.com/"), http=None, settings=None, discovery=discovery)

    findings = await CsrfModule().run(context)

    assert any("CSRF" in f.title for f in findings)
    assert all(f.module == "csrf" for f in findings)
    assert all(f.owasp_category == "A01:2021-Broken Access Control" for f in findings)


async def test_csrf_module_no_false_positive_when_token_required_and_enforced(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return httpx.Response(403, text="invalid csrf token")
        return httpx.Response(200, text='<input type="hidden" name="csrf_token" value="realtoken1234567890123456">')

    def _fake_client(*, max_concurrency, timeout, max_retries):
        return AsyncHttpClient(
            max_concurrency=max_concurrency, max_retries=max_retries, timeout=5.0,
            transport=httpx.MockTransport(handler),
        )

    monkeypatch.setattr(csrf_module, "AsyncHttpClient", _fake_client)

    discovery = DiscoveryResult(
        target_url="https://example.com/", final_url="https://example.com/", ok=True,
        targets=[ParamTarget(method="post", url="https://example.com/settings", params=["email", "csrf_token"], defaults={"email": "", "csrf_token": "realtoken1234567890123456"})],
    )
    context = ScanContext(target=ScanTarget(url="https://example.com/"), http=None, settings=None, discovery=discovery)

    findings = await CsrfModule().run(context)
    assert findings == []


async def test_csrf_module_returns_empty_when_discovery_failed():
    discovery = DiscoveryResult(target_url="https://x/", final_url="https://x/", ok=False)
    context = ScanContext(target=ScanTarget(url="https://x/"), http=None, settings=None, discovery=discovery)
    assert await CsrfModule().run(context) == []


async def test_csrf_module_returns_empty_when_no_post_targets():
    discovery = DiscoveryResult(
        target_url="https://x/", final_url="https://x/", ok=True,
        targets=[ParamTarget(method="get", url="https://x/search", params=["q"], defaults={})],
    )
    context = ScanContext(target=ScanTarget(url="https://x/"), http=None, settings=None, discovery=discovery)
    assert await CsrfModule().run(context) == []
