from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

from owasp_inspector.discovery.models import (
    CookieFlags,
    DiscoveryResult,
    Fingerprint,
    ParamTarget,
    RobotsInfo,
    TlsInfo,
)

_DEFAULT_CACHE_DIR = Path("Data") / "scan_cache"


def _cache_key(url: str) -> str:
    return hashlib.sha256(url.encode("utf-8")).hexdigest()[:24]


def _to_dict(discovery: DiscoveryResult) -> dict:
    return {
        "target_url": discovery.target_url,
        "final_url": discovery.final_url,
        "ok": discovery.ok,
        "status_code": discovery.status_code,
        "headers": discovery.headers,
        "cookies": discovery.cookies,
        "fingerprint": {
            "technology": discovery.fingerprint.technology,
            "confidence": discovery.fingerprint.confidence,
            "evidence": discovery.fingerprint.evidence,
        },
        "tls": {
            "inspected": discovery.tls.inspected,
            "version": discovery.tls.version,
            "subject": discovery.tls.subject,
            "issuer": discovery.tls.issuer,
            "not_after": discovery.tls.not_after,
            "error": discovery.tls.error,
        },
        "robots": {
            "fetched": discovery.robots.fetched,
            "disallowed_paths": discovery.robots.disallowed_paths,
            "sitemap_urls": discovery.robots.sitemap_urls,
        },
        "sitemap_urls": discovery.sitemap_urls,
        "crawled_urls": discovery.crawled_urls,
        "targets": [{"method": t.method, "url": t.url, "params": t.params} for t in discovery.targets],
        "cookie_flags": [
            {"name": c.name, "secure": c.secure, "httponly": c.httponly, "samesite": c.samesite}
            for c in discovery.cookie_flags
        ],
    }


def _from_dict(data: dict) -> DiscoveryResult:
    return DiscoveryResult(
        target_url=data["target_url"],
        final_url=data["final_url"],
        ok=data["ok"],
        status_code=data.get("status_code"),
        headers=data.get("headers", {}),
        cookies=data.get("cookies", {}),
        fingerprint=Fingerprint(**data.get("fingerprint", {})) if data.get("fingerprint") else Fingerprint(),
        tls=TlsInfo(**data.get("tls", {})) if data.get("tls") else TlsInfo(),
        # `parser` is intentionally not restored from cache (a RobotFileParser isn't
        # JSON-serializable and can't be losslessly reconstructed from disallowed_paths
        # alone) — safe because a resumed scan reuses discovery wholesale and never
        # re-crawls, so nothing calls RobotsInfo.allows() again on this instance.
        robots=RobotsInfo(
            fetched=data.get("robots", {}).get("fetched", False),
            disallowed_paths=data.get("robots", {}).get("disallowed_paths", []),
            sitemap_urls=data.get("robots", {}).get("sitemap_urls", []),
        ),
        sitemap_urls=data.get("sitemap_urls", []),
        crawled_urls=data.get("crawled_urls", []),
        targets=[ParamTarget(**t) for t in data.get("targets", [])],
        cookie_flags=[CookieFlags(**c) for c in data.get("cookie_flags", [])],
    )


class DiscoveryCache:
    """Caches a completed DiscoveryResult to disk, keyed by target URL.

    This is what "resume" means for this engine: discovery (the crawl,
    fingerprinting, TLS/robots/sitemap fetching) is the one genuinely
    expensive, re-runnable-independently phase. If a scan is interrupted
    (killed, crashed) after discovery completed, a resumed run can skip
    straight back to it instead of re-crawling the target from scratch.

    This does NOT checkpoint progress *inside* a module (e.g. how far the
    SQLi engine got through its payload list) — modules don't have
    persisted internal state to resume from, and faking that would just be
    an empty flag with no real effect. Scoped honestly to the part that
    actually has something worth saving.
    """

    def __init__(self, cache_dir: Path | None = None):
        self.cache_dir = cache_dir or _DEFAULT_CACHE_DIR

    def _path_for(self, url: str) -> Path:
        return self.cache_dir / f"{_cache_key(url)}.json"

    def save(self, url: str, discovery: DiscoveryResult) -> None:
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        payload = {"cached_at": time.time(), "discovery": _to_dict(discovery)}
        self._path_for(url).write_text(json.dumps(payload), encoding="utf-8")

    def load(self, url: str, max_age_seconds: float = 3600.0) -> DiscoveryResult | None:
        path = self._path_for(url)
        if not path.exists():
            return None
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None
        if time.time() - payload.get("cached_at", 0) > max_age_seconds:
            return None
        try:
            return _from_dict(payload["discovery"])
        except (KeyError, TypeError):
            return None
