import httpx

from owasp_inspector.core.http import AsyncHttpClient
from owasp_inspector.discovery import fingerprint as fp_module
from owasp_inspector.discovery.fingerprint import fingerprint_target

FAKE_SIGNATURES = {
    "django": {
        "headers": [{"name": "server", "pattern": "(?i)wsgiserver|gunicorn"}],
        "cookies": [{"name": "csrftoken"}],
        "html_patterns": ["csrfmiddlewaretoken"],
    },
    "laravel": {
        "headers": [],
        "cookies": [{"name": "laravel_session"}],
        "html_patterns": ["_token"],
    },
}


def test_pattern_matches_uses_regex():
    assert fp_module._pattern_matches("(?i)wsgiserver|gunicorn", "WSGIServer/0.2") is True
    assert fp_module._pattern_matches("(?i)wsgiserver|gunicorn", "nginx") is False


async def test_fingerprint_picks_highest_scoring_technology(monkeypatch):
    monkeypatch.setattr(fp_module, "_load_signatures", lambda: FAKE_SIGNATURES)

    def handler(request):
        return httpx.Response(
            200,
            headers={"server": "WSGIServer/0.2", "set-cookie": "csrftoken=abc; Path=/"},
            text="<form>csrfmiddlewaretoken</form>",
        )

    async with AsyncHttpClient(transport=httpx.MockTransport(handler)) as http:
        result = await fingerprint_target(http, "https://example.com")
        assert result.technology == "django"
        assert result.confidence == "high"
        assert len(result.evidence) == 3


async def test_fingerprint_returns_unknown_when_nothing_matches(monkeypatch):
    monkeypatch.setattr(fp_module, "_load_signatures", lambda: FAKE_SIGNATURES)

    def handler(request):
        return httpx.Response(200, text="<html>plain page</html>")

    async with AsyncHttpClient(transport=httpx.MockTransport(handler)) as http:
        result = await fingerprint_target(http, "https://example.com")
        assert result.technology == "unknown"
        assert result.confidence == "none"


async def test_fingerprint_returns_unknown_when_no_signatures_available(monkeypatch):
    monkeypatch.setattr(fp_module, "_load_signatures", lambda: {})

    def handler(request):
        return httpx.Response(200, text="anything")

    async with AsyncHttpClient(transport=httpx.MockTransport(handler)) as http:
        result = await fingerprint_target(http, "https://example.com")
        assert result.technology == "unknown"
