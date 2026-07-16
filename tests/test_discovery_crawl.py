import httpx

from owasp_inspector.core.http import AsyncHttpClient
from owasp_inspector.discovery.crawl import crawl
from owasp_inspector.discovery.models import RobotsInfo

PAGES = {
    "/": """
        <html><body>
            <a href="/search?q=test">search</a>
            <a href="/admin/panel">admin</a>
            <a href="https://other-site.com/x">offsite</a>
            <a href="/logo.png">logo</a>
            <form action="/login" method="post">
                <input name="username"><input name="password">
            </form>
        </body></html>
    """,
    "/search": "<html><body>results page, no links</body></html>",
    "/admin/panel": "<html><body>secret admin</body></html>",
}


def _handler(request):
    path = request.url.path
    if path in PAGES:
        return httpx.Response(200, headers={"content-type": "text/html"}, text=PAGES[path])
    return httpx.Response(404)


async def test_crawl_discovers_get_and_post_targets():
    async with AsyncHttpClient(transport=httpx.MockTransport(_handler)) as http:
        crawled, targets = await crawl(http, "https://example.com/", max_pages=10)

    get_targets = [t for t in targets if t.method == "get"]
    post_targets = [t for t in targets if t.method == "post"]

    assert any(t.url == "https://example.com/search" and t.params == ["q"] for t in get_targets)
    assert any(
        t.url == "https://example.com/login" and set(t.params) == {"username", "password"}
        for t in post_targets
    )


async def test_crawl_stays_same_origin_and_skips_static_assets():
    async with AsyncHttpClient(transport=httpx.MockTransport(_handler)) as http:
        crawled, _ = await crawl(http, "https://example.com/", max_pages=10)

    assert not any("other-site.com" in url for url in crawled)
    assert not any(url.endswith(".png") for url in crawled)


async def test_crawl_respects_robots_disallow():
    robots = RobotsInfo(fetched=True, disallowed_paths=["/admin/"])

    class _Parser:
        def can_fetch(self, agent, url):
            return "/admin/" not in url

    robots.parser = _Parser()

    async with AsyncHttpClient(transport=httpx.MockTransport(_handler)) as http:
        crawled, _ = await crawl(http, "https://example.com/", max_pages=10, robots=robots)

    assert not any("/admin/panel" in url for url in crawled)


async def test_crawl_respects_max_pages_limit():
    async with AsyncHttpClient(transport=httpx.MockTransport(_handler)) as http:
        crawled, _ = await crawl(http, "https://example.com/", max_pages=1)

    assert len(crawled) <= 1
