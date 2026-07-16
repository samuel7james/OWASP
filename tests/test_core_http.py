import httpx

from owasp_inspector.core.http import AsyncHttpClient


async def test_get_returns_response_on_success():
    def handler(request):
        return httpx.Response(200, text="ok")

    client = AsyncHttpClient(max_retries=0, transport=httpx.MockTransport(handler))
    try:
        response = await client.get("https://example.com")
        assert response.status_code == 200
        assert response.text == "ok"
    finally:
        await client.aclose()


async def test_retries_on_retryable_status_then_succeeds():
    attempts = {"n": 0}

    def handler(request):
        attempts["n"] += 1
        if attempts["n"] < 3:
            return httpx.Response(503)
        return httpx.Response(200, text="ok")

    client = AsyncHttpClient(max_retries=3, backoff_base_seconds=0.01, transport=httpx.MockTransport(handler))
    try:
        response = await client.get("https://example.com")
        assert response.status_code == 200
        assert attempts["n"] == 3
    finally:
        await client.aclose()


async def test_gives_up_after_max_retries():
    def handler(request):
        return httpx.Response(503)

    client = AsyncHttpClient(max_retries=2, backoff_base_seconds=0.01, transport=httpx.MockTransport(handler))
    try:
        response = await client.get("https://example.com")
        assert response.status_code == 503
    finally:
        await client.aclose()


async def test_network_error_returns_none_after_retries():
    def handler(request):
        raise httpx.ConnectError("boom", request=request)

    client = AsyncHttpClient(max_retries=1, backoff_base_seconds=0.01, transport=httpx.MockTransport(handler))
    try:
        response = await client.get("https://example.com")
        assert response is None
    finally:
        await client.aclose()


async def test_context_manager_closes_client():
    def handler(request):
        return httpx.Response(200)

    async with AsyncHttpClient(transport=httpx.MockTransport(handler)) as client:
        response = await client.get("https://example.com")
        assert response.status_code == 200
