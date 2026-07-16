from __future__ import annotations

import urllib.parse

from owasp_inspector.core.http import AsyncHttpClient
from owasp_inspector.discovery.models import ProbeResult


def normalize_url(url: str) -> str:
    url = url.strip()
    if "://" not in url:
        url = f"http://{url}"
    parsed = urllib.parse.urlparse(url)
    path = parsed.path or "/"
    return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, path, parsed.params, parsed.query, parsed.fragment))


def _candidate_urls(url: str) -> list[str]:
    """Original URL plus an https upgrade attempt for http-only input."""
    parsed = urllib.parse.urlparse(url)
    candidates = [url]
    if parsed.scheme == "http":
        candidates.append(urllib.parse.urlunparse(("https",) + parsed[1:]))
    return candidates


async def probe_target(http: AsyncHttpClient, url: str) -> ProbeResult:
    """Confirm the target responds, trying an https upgrade for http:// input."""
    normalized = normalize_url(url)
    last_error = "unknown error"

    for candidate in _candidate_urls(normalized):
        response = await http.get(candidate)
        if response is not None:
            return ProbeResult(ok=True, final_url=str(response.url), status_code=response.status_code)
        last_error = f"no response from {candidate}"

    return ProbeResult(ok=False, final_url=normalized, status_code=None, error=last_error)
