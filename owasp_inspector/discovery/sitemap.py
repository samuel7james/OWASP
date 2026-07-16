from __future__ import annotations

import urllib.parse
import xml.etree.ElementTree as ET

from owasp_inspector.core.http import AsyncHttpClient


async def fetch_sitemap(http: AsyncHttpClient, base_url: str, sitemap_hints: list[str] | None = None) -> list[str]:
    """Fetch and parse sitemap.xml (or robots.txt-declared Sitemap: URLs), returning listed page URLs."""
    parsed = urllib.parse.urlparse(base_url)
    default_sitemap = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, "/sitemap.xml", "", "", ""))
    candidates = list(dict.fromkeys((sitemap_hints or []) + [default_sitemap]))

    urls: list[str] = []
    for sitemap_url in candidates:
        response = await http.get(sitemap_url)
        if response is None or response.status_code >= 400:
            continue
        try:
            root = ET.fromstring(response.text)
        except ET.ParseError:
            continue
        for elem in root.iter():
            if elem.tag.endswith("loc") and elem.text:
                urls.append(elem.text.strip())

    return list(dict.fromkeys(urls))
