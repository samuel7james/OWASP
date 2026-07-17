from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

import owasp_inspector.modules  # noqa: F401  (import side effect: registers built-in modules)
from owasp_inspector.core.config import get_settings
from owasp_inspector.core.discovery_cache import DiscoveryCache
from owasp_inspector.core.http import AsyncHttpClient
from owasp_inspector.core.lifecycle import Scan
from owasp_inspector.core.logging_config import configure_logging
from owasp_inspector.core.models import Finding, ScanTarget
from owasp_inspector.core.module import ScanContext
from owasp_inspector.core.profiles import get_profile
from owasp_inspector.core.registry import ModuleRegistry, default_registry
from owasp_inspector.discovery.engine import run_discovery
from owasp_inspector.discovery.models import DiscoveryResult

logger = logging.getLogger(__name__)


@dataclass
class ScanResult:
    scan: Scan
    discovery: DiscoveryResult
    findings: list[Finding]


async def run_scan(
    url: str,
    *,
    profile: str | None = None,
    max_pages: int = 40,
    registry: ModuleRegistry | None = None,
    resume: bool = False,
    discovery_cache: DiscoveryCache | None = None,
    respect_robots: bool = False,
) -> ScanResult:
    """Run discovery once, then every registered module against that same
    result, concurrently. This is the single entry point Phase 7's CLI calls
    for `owasp-inspector <url>` — one URL in, every applicable OWASP category
    assessed automatically.

    `resume=True` reuses a cached discovery result for this exact URL (if one
    completed within the cache's freshness window) instead of re-crawling —
    the genuinely expensive, independently-re-runnable phase. It does not
    checkpoint progress inside a module; modules have no persisted internal
    state to resume from.

    `respect_robots=False` by default: robots.txt is a crawler-politeness
    convention, not an access-control mechanism, and this only ever runs
    after the authorization gate already confirmed the scan is permitted —
    see crawl()'s docstring for the live-target case that motivated this.
    """
    configure_logging()
    scan_profile = get_profile(profile)
    registry = registry or default_registry
    cache = discovery_cache or DiscoveryCache()

    scan_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-") + uuid.uuid4().hex[:8]
    scan = Scan(scan_id, url)
    scan.start()

    try:
        async with AsyncHttpClient(
            max_concurrency=scan_profile.max_concurrency,
            timeout=scan_profile.timeout,
            max_retries=scan_profile.max_retries,
            min_request_interval_seconds=scan_profile.min_request_interval_seconds,
        ) as http:
            discovery = cache.load(url) if resume else None
            resumed = discovery is not None
            if discovery is None:
                discovery = await run_discovery(http, url, max_pages=max_pages, respect_robots=respect_robots)
                if discovery.ok:
                    cache.save(url, discovery)
            scan.history[-1].detail = "resumed from cached discovery" if resumed else None

            context = ScanContext(target=ScanTarget(url=url), http=http, settings=get_settings(), discovery=discovery)

            modules = registry.instantiate_all()
            results = await asyncio.gather(*(m.run(context) for m in modules), return_exceptions=True)

            findings: list[Finding] = []
            for module, result in zip(modules, results):
                if isinstance(result, Exception):
                    # A module's failure (network hiccup, unexpected response shape) must not
                    # sink the rest of the scan — this is what "modules remain independent" means.
                    logger.warning("Module %s failed: %s", module.name, result)
                    continue
                findings.extend(result)
    except Exception as exc:
        scan.fail(str(exc))
        raise

    scan.complete()
    return ScanResult(scan=scan, discovery=discovery, findings=findings)
