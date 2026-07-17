import httpx

from owasp_inspector.core.http import AsyncHttpClient
from owasp_inspector.modules.sqli.builtin import BuiltinSqliScanner
from owasp_inspector.modules.sqli.context import SqliContext
from owasp_inspector.modules.sqli.payloads import load_sqli_payloads

_SQL_ERROR_BODY = "Warning: mysql_fetch_array(): supplied argument is not a valid MySQL result resource"


def _vulnerable_handler(request: httpx.Request) -> httpx.Response:
    """Simulates a classic error-based SQLi: a bare `'` in the `id` param
    breaks the query and leaks a MySQL error; anything else is a normal page."""
    query = httpx.QueryParams(request.url.query)
    id_value = query.get("id", "")
    if "'" in id_value:
        return httpx.Response(200, text=_SQL_ERROR_BODY)
    return httpx.Response(200, text=f"<html><body>Item #{id_value}</body></html>")


def _clean_handler(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, text="<html><body>nothing interesting here</body></html>")


async def test_detects_error_based_sqli_on_vulnerable_target():
    http = AsyncHttpClient(transport=httpx.MockTransport(_vulnerable_handler), max_retries=0)
    ctx = SqliContext(http, load_sqli_payloads())
    scanner = BuiltinSqliScanner(http, ctx, max_concurrency=10)

    targets = [("get", {"url": "https://example.com/item", "params": ["id"], "defaults": {"id": "1"}})]
    vulns, candidates = await scanner.scan(targets)
    await http.aclose()

    assert any("Error Pattern Match" in v["type"] for v in vulns)
    error_finding = next(v for v in vulns if "Error Pattern Match" in v["type"])
    assert error_finding["parameter"] == "id"
    assert error_finding["status"] == "confirmed"


async def test_does_not_flag_error_pattern_already_present_in_baseline():
    # Found via live testing against a real target (DVWA with an uninitialized
    # DB): the baseline response for a param can already contain a DB error
    # caused by a *different* parameter's empty default, unrelated to whatever
    # payload is under test. Without a baseline guard, every single payload
    # "matches" that pre-existing error — a false-positive storm, not signal.
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=_SQL_ERROR_BODY)  # always errors, regardless of payload

    http = AsyncHttpClient(transport=httpx.MockTransport(handler), max_retries=0)
    ctx = SqliContext(http, load_sqli_payloads())
    scanner = BuiltinSqliScanner(http, ctx, max_concurrency=10)

    targets = [
        ("get", {"url": "https://example.com/item", "params": ["Submit"], "defaults": {"id": "", "Submit": "Submit"}})
    ]
    vulns, candidates = await scanner.scan(targets)
    await http.aclose()

    assert not any("Error Pattern Match" in v["type"] for v in vulns)


async def test_no_findings_on_clean_target():
    http = AsyncHttpClient(transport=httpx.MockTransport(_clean_handler), max_retries=0)
    ctx = SqliContext(http, load_sqli_payloads())
    scanner = BuiltinSqliScanner(http, ctx, max_concurrency=10)

    targets = [("get", {"url": "https://example.com/page", "params": ["q"], "defaults": {"q": "hello"}})]
    vulns, candidates = await scanner.scan(targets)
    await http.aclose()

    assert vulns == []


async def test_empty_targets_returns_no_findings():
    http = AsyncHttpClient(transport=httpx.MockTransport(_clean_handler), max_retries=0)
    ctx = SqliContext(http, load_sqli_payloads())
    scanner = BuiltinSqliScanner(http, ctx, max_concurrency=10)

    vulns, candidates = await scanner.scan([])
    await http.aclose()

    assert vulns == []
    assert candidates == []


async def test_post_target_with_csrf_field_is_handled():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>ok</html>")

    http = AsyncHttpClient(transport=httpx.MockTransport(handler), max_retries=0)
    ctx = SqliContext(http, load_sqli_payloads())
    scanner = BuiltinSqliScanner(http, ctx, max_concurrency=10)

    targets = [
        (
            "post",
            {
                "url": "https://example.com/comment",
                "params": ["body", "csrf_token"],
                "defaults": {"body": "hi", "csrf_token": "tok"},
            },
        )
    ]
    vulns, candidates = await scanner.scan(targets)
    await http.aclose()

    # csrf_token itself must never be treated as an injectable parameter
    assert not any(v.get("parameter") == "csrf_token" for v in vulns + candidates)
