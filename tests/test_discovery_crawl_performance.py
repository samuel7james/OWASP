import asyncio
import time

import httpx

from owasp_inspector.core.http import AsyncHttpClient
from owasp_inspector.discovery.crawl import crawl

_PAGE_LATENCY_SECONDS = 0.2
_WIDTH = 8  # links per page, so an entire wave's worth of pages is fetchable at once


def _page(i: int) -> str:
    links = "".join(f'<a href="/p{i}_{j}"></a>' for j in range(_WIDTH))
    return f"<html><body>{links}</body></html>"


async def _slow_handler(request: httpx.Request) -> httpx.Response:
    await asyncio.sleep(_PAGE_LATENCY_SECONDS)
    path = request.url.path
    if path == "/":
        return httpx.Response(200, headers={"content-type": "text/html"}, text=_page(0))
    return httpx.Response(200, headers={"content-type": "text/html"}, text="<html><body>leaf page</body></html>")


async def test_crawl_fetches_a_wave_concurrently_not_sequentially():
    """With N same-depth pages each taking _PAGE_LATENCY_SECONDS, a sequential
    crawl takes N * latency; a wave-concurrent crawl (bounded by
    AsyncHttpClient's own concurrency cap) takes ~1 * latency per wave.
    This is a real, deterministic proxy for the "fetch a BFS wave
    concurrently" performance change — not a live-network timing that could
    be flaky, but not faked either: it fails if crawl.py regresses to
    fetching one-at-a-time.
    """
    async with AsyncHttpClient(max_concurrency=_WIDTH, transport=httpx.MockTransport(_slow_handler)) as http:
        start = time.monotonic()
        crawled, _ = await crawl(http, "https://example.com/", max_pages=1 + _WIDTH)
        elapsed = time.monotonic() - start

    assert len(crawled) == 1 + _WIDTH
    # Sequential would take (1 + WIDTH) * latency ~= 1.8s. Concurrent waves
    # take ~2 * latency (root page, then the whole second wave at once) plus
    # overhead. Generous upper bound well under the sequential figure.
    assert elapsed < _PAGE_LATENCY_SECONDS * (1 + _WIDTH) * 0.6, f"crawl took {elapsed:.2f}s — looks sequential, not concurrent"
