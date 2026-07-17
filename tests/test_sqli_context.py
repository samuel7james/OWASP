import httpx

from owasp_inspector.core.http import AsyncHttpClient
from owasp_inspector.modules.sqli.context import SqliContext
from owasp_inspector.modules.sqli.payloads import SqliPayloadSet


def _ctx(handler):
    http = AsyncHttpClient(transport=httpx.MockTransport(handler), max_retries=0)
    return SqliContext(http, SqliPayloadSet(error_patterns=[r"you have an error in your sql syntax"]))


def test_detect_waf_recognizes_cloudflare():
    ctx = _ctx(lambda r: httpx.Response(200))
    response = httpx.Response(403, text="Attention Required! | Cloudflare")
    assert ctx.detect_waf(response) == "Cloudflare"


def test_detect_waf_returns_none_for_clean_response():
    ctx = _ctx(lambda r: httpx.Response(200))
    assert ctx.detect_waf(httpx.Response(200, text="<html>ok</html>")) is None


def test_detect_sql_errors_matches_known_pattern():
    ctx = _ctx(lambda r: httpx.Response(200))
    assert ctx.detect_sql_errors("You have an error in your SQL syntax; check the manual") is True
    assert ctx.detect_sql_errors("everything is fine") is False


def test_strip_payload_echoes_removes_encoded_variants():
    ctx = _ctx(lambda r: httpx.Response(200))
    text = "before &#x27;marker&#x27; after"
    stripped = ctx.strip_payload_echoes(text, "'marker'", "marker")
    assert "&#x27;marker&#x27;" not in stripped


def test_inject_url_param_replaces_existing_param():
    result = SqliContext.inject_url_param("https://x.test/page?id=1&x=2", "id", "9")
    assert "id=9" in result
    assert "x=2" in result


def test_is_likely_auth_target_detects_login_param_and_path():
    assert SqliContext.is_likely_auth_target("post", "https://x/login", "username", {}) is True
    assert SqliContext.is_likely_auth_target("get", "https://x/search", "q", {}) is False
    assert SqliContext.is_likely_auth_target("post", "https://x/form", "password", {}) is True


async def test_refresh_csrf_extracts_token_from_hidden_input():
    def handler(request):
        return httpx.Response(200, text='<input type="hidden" name="csrf_token" value="abc123">')

    ctx = _ctx(handler)
    data = await ctx.refresh_csrf("https://x/page", {"csrf_token": "", "other": "1"})
    assert data["csrf_token"] == "abc123"
    assert data["other"] == "1"


async def test_refresh_csrf_leaves_data_unchanged_when_no_csrf_keys_present():
    ctx = _ctx(lambda r: httpx.Response(200))
    data = await ctx.refresh_csrf("https://x/page", {"q": "1"})
    assert data == {"q": "1"}


async def test_reflection_control_matches_true_when_benign_value_also_reflects():
    def handler(request):
        return httpx.Response(200, text="echo: abc")

    ctx = _ctx(handler)
    matched = await ctx.reflection_control_matches("get", "https://x/search", "q", {"q": ""}, "xyz")
    assert matched is True
