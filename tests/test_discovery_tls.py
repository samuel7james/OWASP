from owasp_inspector.discovery.tls import inspect_tls


async def test_http_scheme_is_not_inspected():
    result = await inspect_tls("http://example.com/page")
    assert result.inspected is False
    assert result.error is None


async def test_connection_failure_is_handled_gracefully():
    # Port 1 is reserved/unlikely to accept TLS connections in any test environment.
    result = await inspect_tls("https://127.0.0.1:1/", timeout=1.0)
    assert result.inspected is False
    assert result.error is not None
