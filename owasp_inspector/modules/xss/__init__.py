from __future__ import annotations

from owasp_inspector.core.http import AsyncHttpClient
from owasp_inspector.core.models import Finding
from owasp_inspector.core.module import Module, ScanContext
from owasp_inspector.core.registry import register_module
from owasp_inspector.modules._raw_finding import finding_from_raw
from owasp_inspector.modules.xss.context import XssContext
from owasp_inspector.modules.xss.payloads import load_xss_payloads
from owasp_inspector.modules.xss.reflected import ReflectedXssScanner


def _param_targets(discovery) -> list[tuple[str, dict]]:
    return [(t.method, {"url": t.url, "params": t.params, "defaults": t.defaults}) for t in discovery.targets]


@register_module
class XssModule(Module):
    """Native async reflected-XSS module (the most common,
    always-applicable XSS check): standard payload sweep plus a
    context-aware follow-up pass that picks JS-string/event-handler/
    attribute-breakout payloads based on where the injected canary landed.

    Uses shared discovery (context.discovery.targets) instead of crawling
    independently, and its own AsyncHttpClient with retries disabled — an
    XSS probe response that happens to 5xx should be observed as-is, not
    silently retried into something else.

    Not covered: Stored XSS, DOM XSS (static JS source/sink analysis +
    dynamic probing), and CSP-bypass scanning — each a substantially
    larger, more specialized engine than reflected XSS.
    """

    name = "xss"
    owasp_category = "A03:2021-Injection"

    async def run(self, context: ScanContext) -> list[Finding]:
        discovery = context.discovery
        if discovery is None or not discovery.ok:
            return []

        targets = _param_targets(discovery)
        if not targets:
            return []

        settings = context.settings
        max_concurrency = getattr(settings, "scan_sqli_workers", 10) if settings else 10

        async with AsyncHttpClient(max_concurrency=max_concurrency, timeout=15.0, max_retries=0) as http:
            xss_ctx = XssContext(http, load_xss_payloads(), cookie=context.target.cookie)
            scanner = ReflectedXssScanner(xss_ctx, max_concurrency=max_concurrency)
            vulns = await scanner.scan(targets)
            vulns.extend(await scanner.scan_context_aware(targets, vulns))

        return [
            finding_from_raw(v, module=self.name, owasp_category=self.owasp_category, target_url=discovery.final_url)
            for v in vulns
        ]
