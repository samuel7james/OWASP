from __future__ import annotations

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
    params = list(dict.fromkeys(urllib.parse.parse_qs(parsed.query).keys()))
    if not params:
        return None
    clean_url = urllib.parse.urlunparse(parsed._replace(query=""))
    return ParamTarget(method="get", url=clean_url, params=params)


def _extract_forms(html: str, page_url: str) -> list[ParamTarget]:
    soup = BeautifulSoup(html, "html.parser")
    targets: list[ParamTarget] = []
    for form in soup.find_all("form"):
        action = form.get("action") or page_url
        method = (form.get("method") or "get").strip().lower()
        action_url = urllib.parse.urljoin(page_url, action)
        params = list(dict.fromkeys(
            field.get("name") for field in form.find_all(["input", "textarea", "select"]) if field.get("name")
        ))
        if params:
            targets.append(ParamTarget(method="post" if method == "post" else "get", url=action_url, params=params))
    return targets


def _extract_links(html: str, page_url: str) -> list[str]:
    soup = BeautifulSoup(html, "html.parser")
    links = []
    for a in soup.find_all("a", href=True):
        href = urllib.parse.urljoin(page_url, a["href"]).split("#", 1)[0]
        if href:
            links.append(href)
    return links


async def crawl(
    http: AsyncHttpClient, start_url: str, *, max_pages: int = 40, robots: RobotsInfo | None = None
) -> tuple[list[str], list[ParamTarget]]:
    """Breadth-first, same-origin crawl producing every GET/POST parameter target found.

    This is the single shared crawl every assessment module (Phase 5) reads from,
    replacing the legacy design where each scanner (SQLi/XSS/CSRF) crawled the
    target independently and multiplied request volume for no benefit.
    """
    origin_netloc = urllib.parse.urlparse(start_url).netloc
    seen: set[str] = set()
    queue: list[str] = [start_url]
    crawled: list[str] = []
    targets: list[ParamTarget] = []

    while queue and len(crawled) < max_pages:
        url = queue.pop(0)
        if url in seen:
            continue
        seen.add(url)

        if not _same_origin(url, origin_netloc) or not _is_crawlable(url):
            continue
        if robots is not None and not robots.allows(url):
            continue

        get_target = _extract_get_target(url)
        if get_target:
            targets.append(get_target)

        response = await http.get(url)
        if response is None or "text/html" not in response.headers.get("content-type", ""):
            continue

        final_url = str(response.url)
        crawled.append(final_url)
        targets.extend(_extract_forms(response.text, final_url))

        for link in _extract_links(response.text, final_url):
            if link not in seen:
                queue.append(link)

    return crawled, targets
