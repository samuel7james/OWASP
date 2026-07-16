import httpx

from owasp_inspector.core.http import AsyncHttpClient
from owasp_inspector.discovery.robots import fetch_robots

ROBOTS_TXT = """User-agent: *
Disallow: /admin/
Disallow: /private/
Sitemap: https://example.com/sitemap.xml
"""


async def test_fetch_robots_parses_disallow_and_sitemap():
    def handler(request):
        return httpx.Response(200, text=ROBOTS_TXT)

    async with AsyncHttpClient(transport=httpx.MockTransport(handler)) as http:
        robots = await fetch_robots(http, "https://example.com")
        assert robots.fetched is True
        assert "/admin/" in robots.disallowed_paths
        assert robots.sitemap_urls == ["https://example.com/sitemap.xml"]


async def test_robots_allows_respects_disallow_rules():
    def handler(request):
        return httpx.Response(200, text=ROBOTS_TXT)

    async with AsyncHttpClient(transport=httpx.MockTransport(handler)) as http:
        robots = await fetch_robots(http, "https://example.com")
        assert robots.allows("https://example.com/public/page") is True
        assert robots.allows("https://example.com/admin/panel") is False


async def test_fetch_robots_missing_file_returns_unfetched():
    def handler(request):
        return httpx.Response(404)

    async with AsyncHttpClient(transport=httpx.MockTransport(handler)) as http:
        robots = await fetch_robots(http, "https://example.com")
        assert robots.fetched is False
        assert robots.allows("https://example.com/anything") is True
