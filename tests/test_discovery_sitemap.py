import httpx

from owasp_inspector.core.http import AsyncHttpClient
from owasp_inspector.discovery.sitemap import fetch_sitemap

SITEMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://example.com/</loc></url>
  <url><loc>https://example.com/about</loc></url>
</urlset>
"""


async def test_fetch_sitemap_parses_namespaced_loc_tags():
    def handler(request):
        if request.url.path == "/sitemap.xml":
            return httpx.Response(200, text=SITEMAP_XML)
        return httpx.Response(404)

    async with AsyncHttpClient(transport=httpx.MockTransport(handler)) as http:
        urls = await fetch_sitemap(http, "https://example.com")
        assert "https://example.com/" in urls
        assert "https://example.com/about" in urls


async def test_fetch_sitemap_uses_robots_hinted_url():
    def handler(request):
        if request.url.path == "/custom-sitemap.xml":
            return httpx.Response(200, text=SITEMAP_XML)
        return httpx.Response(404)

    async with AsyncHttpClient(transport=httpx.MockTransport(handler)) as http:
        urls = await fetch_sitemap(
            http, "https://example.com", sitemap_hints=["https://example.com/custom-sitemap.xml"]
        )
        assert len(urls) == 2


async def test_fetch_sitemap_returns_empty_on_missing_or_invalid():
    def handler(request):
        return httpx.Response(200, text="not xml at all <<<")

    async with AsyncHttpClient(transport=httpx.MockTransport(handler)) as http:
        urls = await fetch_sitemap(http, "https://example.com")
        assert urls == []
