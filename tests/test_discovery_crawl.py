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
            <a href="/profile?id=5">profile</a>
            <form action="/login" method="post">
                <input name="username" value="guest"><input name="password">
            </form>
        </body></html>
    """,
    "/search": "<html><body>results page, no links</body></html>",
    "/admin/panel": "<html><body>secret admin</body></html>",
    "/profile": "<html><body>no links, has query</body></html>",
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


async def test_crawl_captures_default_values_for_get_and_form_targets():
    async with AsyncHttpClient(transport=httpx.MockTransport(_handler)) as http:
        _, targets = await crawl(http, "https://example.com/", max_pages=10)

    profile_target = next(t for t in targets if t.url == "https://example.com/profile")
    assert profile_target.defaults == {"id": "5"}

    login_target = next(t for t in targets if t.url == "https://example.com/login")
    assert login_target.defaults.get("username") == "guest"
    assert login_target.defaults.get("password") == ""


async def test_crawl_stays_same_origin_and_skips_static_assets():
    async with AsyncHttpClient(transport=httpx.MockTransport(_handler)) as http:
        crawled, _ = await crawl(http, "https://example.com/", max_pages=10)

    assert not any("other-site.com" in url for url in crawled)
    assert not any(url.endswith(".png") for url in crawled)


def _robots_disallowing_admin() -> RobotsInfo:
    robots = RobotsInfo(fetched=True, disallowed_paths=["/admin/"])

    class _Parser:
        def can_fetch(self, agent, url):
            return "/admin/" not in url

    robots.parser = _Parser()
    return robots


async def test_crawl_ignores_robots_disallow_by_default():
    # A real authorized-test target was found with `Disallow: /` in robots.txt
    # during Phase 8 verification — respecting it by default silently blinded
    # the crawl entirely. robots.txt is a crawler-politeness convention, not
    # an access boundary, and this only runs after the authorization gate.
    async with AsyncHttpClient(transport=httpx.MockTransport(_handler)) as http:
        crawled, _ = await crawl(http, "https://example.com/", max_pages=10, robots=_robots_disallowing_admin())

    assert any("/admin/panel" in url for url in crawled)


async def test_crawl_respects_robots_disallow_when_explicitly_requested():
    async with AsyncHttpClient(transport=httpx.MockTransport(_handler)) as http:
        crawled, _ = await crawl(
            http, "https://example.com/", max_pages=10, robots=_robots_disallowing_admin(), respect_robots=True
        )

    assert not any("/admin/panel" in url for url in crawled)


async def test_crawl_respects_max_pages_limit():
    async with AsyncHttpClient(transport=httpx.MockTransport(_handler)) as http:
        crawled, _ = await crawl(http, "https://example.com/", max_pages=1)

    assert len(crawled) <= 1
