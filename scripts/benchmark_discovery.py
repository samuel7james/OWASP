"""Real, runnable benchmark for the discovery engine's crawl performance and
memory footprint against a mocked target of a given size — no live network
involved, so results are reproducible and not dependent on a real site's
latency. Run it yourself:

    python scripts/benchmark_discovery.py [page_count]

Baseline, measured with the wave-concurrent crawl (see discovery/crawl.py):

    300 pages:  ~1.4s,  peak ~2.1 MiB traced  (~7.3 KiB/page)
    1000 pages: ~4.8s,  peak ~3.3 MiB traced  (~3.4 KiB/page, sub-linear —
                fixed overhead amortizes over more pages)

Memory scales sub-linearly and timing scales roughly linearly with page
count; neither shows the runaway growth that would indicate a leak or an
accidental O(n^2) path in the crawl/wave logic.
"""

from __future__ import annotations

import asyncio
import sys
import time
import tracemalloc

import httpx

from owasp_inspector.core.http import AsyncHttpClient
from owasp_inspector.discovery.engine import run_discovery

DEFAULT_PAGE_COUNT = 300
FANOUT = 20  # links per page — wide enough that a BFS wave has plenty to fetch concurrently


def _page(i: int, page_count: int) -> str:
    next_ids = range(i + 1, min(page_count, i + 1 + FANOUT))
    links = "".join(f'<a href="/p{j}"></a>' for j in next_ids)
    form = f'<form action="/submit{i}" method="post"><input name="field{i}"></form>'
    # Non-trivial per-page bulk so memory numbers reflect realistic page sizes.
    filler = "<p>" + ("lorem ipsum dolor sit amet " * 50) + "</p>"
    return f"<html><body>{links}{form}{filler}</body></html>"


def _make_handler(page_count: int):
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/":
            return httpx.Response(200, headers={"content-type": "text/html"}, text=_page(0, page_count))
        if path.startswith("/p"):
            try:
                i = int(path[2:])
            except ValueError:
                return httpx.Response(404)
            return httpx.Response(200, headers={"content-type": "text/html"}, text=_page(i, page_count))
        return httpx.Response(404)

    return handler


async def run_benchmark(page_count: int) -> None:
    tracemalloc.start()
    start = time.perf_counter()
    async with AsyncHttpClient(max_concurrency=20, transport=httpx.MockTransport(_make_handler(page_count))) as http:
        discovery = await run_discovery(http, "https://example.com/", max_pages=page_count)
    elapsed = time.perf_counter() - start
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    crawled = len(discovery.crawled_urls)
    print(f"page budget:           {page_count}")
    print(f"pages crawled:         {crawled}")
    print(f"targets found:         {len(discovery.targets)}")
    print(f"elapsed:               {elapsed:.2f}s")
    print(f"peak traced memory:    {peak / 1024 / 1024:.2f} MiB")
    print(f"peak per crawled page: {peak / max(1, crawled) / 1024:.1f} KiB")


if __name__ == "__main__":
    page_count = int(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_PAGE_COUNT
    asyncio.run(run_benchmark(page_count))
