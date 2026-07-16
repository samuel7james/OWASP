from __future__ import annotations

import urllib.parse
import urllib.robotparser

from owasp_inspector.core.http import AsyncHttpClient
from owasp_inspector.discovery.models import RobotsInfo


async def fetch_robots(http: AsyncHttpClient, base_url: str) -> RobotsInfo:
    parsed = urllib.parse.urlparse(base_url)
    robots_url = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, "/robots.txt", "", "", ""))

    response = await http.get(robots_url)
    if response is None or response.status_code >= 400:
        return RobotsInfo(fetched=False)

    parser = urllib.robotparser.RobotFileParser()
    parser.parse(response.text.splitlines())

    disallowed = [
        line.split(":", 1)[1].strip()
        for line in response.text.splitlines()
        if line.strip().lower().startswith("disallow:") and line.split(":", 1)[1].strip()
    ]
    sitemap_urls = [
        line.split(":", 1)[1].strip()
        for line in response.text.splitlines()
        if line.strip().lower().startswith("sitemap:")
    ]

    return RobotsInfo(fetched=True, disallowed_paths=disallowed, sitemap_urls=sitemap_urls, parser=parser)
