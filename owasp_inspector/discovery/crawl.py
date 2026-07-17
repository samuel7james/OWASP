from __future__ import annotations

import asyncio
import urllib.parse

from bs4 import BeautifulSoup

from owasp_inspector.core.http import AsyncHttpClient
from owasp_inspector.discovery.models import ParamTarget, RobotsInfo

_SKIP_EXTENSIONS = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".css", ".js",
    ".woff", ".woff2", ".ttf", ".pdf", ".zip", ".mp4", ".mp3",
)


def _same_origin(url: str, origin_netloc: str) -> bool:
    return urllib.parse.urlparse(url).netloc == origin_netloc


def _is_crawlable(url: str) -> bool:
    return not urllib.parse.urlparse(url).path.lower().endswith(_SKIP_EXTENSIONS)


def _extract_get_target(url: str) -> ParamTarget | None:
    parsed = urllib.parse.urlparse(url)
    query = urllib.parse.parse_qs(parsed.query)
    params = list(dict.fromkeys(query.keys()))
    if not params:
        return None
    clean_url = urllib.parse.urlunparse(parsed._replace(query=""))
    defaults = {p: query[p][0] for p in params if query.get(p)}
    return ParamTarget(method="get", url=clean_url, params=params, defaults=defaults)


def _extract_forms(html: str, page_url: str) -> list[ParamTarget]:
    soup = BeautifulSoup(html, "html.parser")
    targets: list[ParamTarget] = []
    for form in soup.find_all("form"):
        action = form.get("action") or page_url
        method = (form.get("method") or "get").strip().lower()
        action_url = urllib.parse.urljoin(page_url, action)
        params: list[str] = []
        defaults: dict[str, str] = {}
        for field in form.find_all(["input", "textarea", "select"]):
            name = field.get("name")
            if not name:
                continue
            if name not in defaults:
                params.append(name)
            if field.name == "select":
                selected = field.find("option", selected=True) or field.find("option")
                defaults[name] = (selected.get("value") or selected.get_text()) if selected else ""
            elif field.name == "textarea":
                defaults[name] = field.get_text() or ""
            else:
                defaults[name] = field.get("value") or ""
        params = list(dict.fromkeys(params))
        if params:
            targets.append(
                ParamTarget(method="post" if method == "post" else "get", url=action_url, params=params, defaults=defaults)
            )
    return targets


def _extract_links(html: str, page_url: str) -> list[str]:
    soup = BeautifulSoup(html, "html.parser")
    links = []
    for a in soup.find_all("a", href=True):
        href = urllib.parse.urljoin(page_url, a["href"]).split("#", 1)[0]
        if href:
            links.append(href)
    return links


def _filter_wave(
    urls: list[str], *, origin_netloc: str, robots: RobotsInfo | None, respect_robots: bool, budget: int
) -> list[str]:
    """Same-origin/crawlable URLs from this wave, capped to the remaining
    page budget, so a wave never fetches more than needed."""
    wave: list[str] = []
    for url in urls:
        if len(wave) >= budget:
            break
        if not _same_origin(url, origin_netloc) or not _is_crawlable(url):
            continue
        if respect_robots and robots is not None and not robots.allows(url):
            continue
        wave.append(url)
    return wave


async def crawl(
    http: AsyncHttpClient,
    start_url: str,
    *,
    max_pages: int = 40,
    robots: RobotsInfo | None = None,
    respect_robots: bool = False,
) -> tuple[list[str], list[ParamTarget]]:
    """Breadth-first, same-origin crawl producing every GET/POST parameter target found.

    This is the single shared crawl every assessment module (Phase 5) reads from,
    replacing the legacy design where each scanner (SQLi/XSS/CSRF) crawled the
    target independently and multiplied request volume for no benefit.

    Fetches each BFS wave (all same-depth pages) concurrently rather than one
    page at a time — actual concurrency is still bounded by AsyncHttpClient's
    own semaphore, so this is purely "stop waiting on page N+1 until page N's
    response arrives" with no change to how many requests are in flight at once.

    `respect_robots` defaults to False: robots.txt is a crawler-politeness
    convention for search engines, not an access-control mechanism, and this
    engine only ever runs after the authorization gate already confirmed the
    scan is permitted. A real live-authorized-test target was found during
    Phase 8 verification with `Disallow: /` in its robots.txt — respecting
    it by default silently blinded the entire crawl on an already-authorized
    target. Set `respect_robots=True` for a more conservative/stealth run.
    """
    origin_netloc = urllib.parse.urlparse(start_url).netloc
    seen: set[str] = {start_url}
    frontier: list[str] = [start_url]
    crawled: list[str] = []
    targets: list[ParamTarget] = []

    while frontier and len(crawled) < max_pages:
        wave = _filter_wave(
            frontier, origin_netloc=origin_netloc, robots=robots, respect_robots=respect_robots,
            budget=max_pages - len(crawled),
        )
        frontier = []
        if not wave:
            continue

        for url in wave:
            get_target = _extract_get_target(url)
            if get_target:
                targets.append(get_target)

        responses = await asyncio.gather(*(http.get(url) for url in wave))

        next_frontier: list[str] = []
        for response in responses:
            if response is None or "text/html" not in response.headers.get("content-type", ""):
                continue

            final_url = str(response.url)
            crawled.append(final_url)
            targets.extend(_extract_forms(response.text, final_url))

            if len(crawled) >= max_pages:
                continue
            for link in _extract_links(response.text, final_url):
                if link not in seen:
                    seen.add(link)
                    next_frontier.append(link)

        frontier = next_frontier

    return crawled, targets
