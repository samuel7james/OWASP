from __future__ import annotations

import asyncio

from owasp_inspector.core.http import AsyncHttpClient
from owasp_inspector.discovery.crawl import crawl
from owasp_inspector.discovery.fingerprint import fingerprint_target
from owasp_inspector.discovery.models import DiscoveryResult
from owasp_inspector.discovery.robots import fetch_robots
from owasp_inspector.discovery.sitemap import fetch_sitemap
from owasp_inspector.discovery.target import probe_target
from owasp_inspector.discovery.tls import inspect_tls


async def run_discovery(http: AsyncHttpClient, url: str, *, max_pages: int = 40) -> DiscoveryResult:
    """Single entry point that replaces per-module discovery: probe, fingerprint,
    TLS/robots/sitemap collection, and one shared crawl, all in one pass."""
    probe = await probe_target(http, url)
    if not probe.ok:
        return DiscoveryResult(target_url=url, final_url=probe.final_url, ok=False, status_code=None)

    final_url = probe.final_url

    robots, fingerprint, tls, initial_response = await asyncio.gather(
        fetch_robots(http, final_url),
        fingerprint_target(http, final_url),
        inspect_tls(final_url),
        http.get(final_url),
    )

    sitemap_urls = await fetch_sitemap(http, final_url, sitemap_hints=robots.sitemap_urls)
    crawled_urls, targets = await crawl(http, final_url, max_pages=max_pages, robots=robots)

    return DiscoveryResult(
        target_url=url,
        final_url=final_url,
        ok=True,
        status_code=probe.status_code,
        headers=dict(initial_response.headers) if initial_response is not None else {},
        cookies=dict(initial_response.cookies) if initial_response is not None else {},
        fingerprint=fingerprint,
        tls=tls,
        robots=robots,
        sitemap_urls=sitemap_urls,
        crawled_urls=crawled_urls,
        targets=targets,
    )
