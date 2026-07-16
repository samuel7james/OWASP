from __future__ import annotations

import asyncio
import logging

import owasp_inspector.modules  # noqa: F401  (import side effect: registers built-in modules)
from owasp_inspector.core.config import get_settings
from owasp_inspector.core.http import AsyncHttpClient
from owasp_inspector.core.logging_config import configure_logging
from owasp_inspector.core.models import Finding, ScanTarget
from owasp_inspector.core.module import ScanContext
from owasp_inspector.core.profiles import get_profile
from owasp_inspector.core.registry import ModuleRegistry, default_registry
from owasp_inspector.discovery.engine import run_discovery
from owasp_inspector.discovery.models import DiscoveryResult

logger = logging.getLogger(__name__)


async def run_scan(
    url: str,
    *,
    profile: str | None = None,
    max_pages: int = 40,
    registry: ModuleRegistry | None = None,
) -> tuple[DiscoveryResult, list[Finding]]:
    """Run discovery once, then every registered module against that same
    result, concurrently. This is the single entry point Phase 7's CLI calls
    for `owasp-inspector <url>` — one URL in, every applicable OWASP category
    assessed automatically.
    """
    configure_logging()
    scan_profile = get_profile(profile)
    registry = registry or default_registry

    async with AsyncHttpClient(
        max_concurrency=scan_profile.max_concurrency,
        timeout=scan_profile.timeout,
        max_retries=scan_profile.max_retries,
        min_request_interval_seconds=scan_profile.min_request_interval_seconds,
    ) as http:
        discovery = await run_discovery(http, url, max_pages=max_pages)
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

        return discovery, findings
