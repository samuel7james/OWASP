from __future__ import annotations

from owasp_inspector.core.http import AsyncHttpClient
from owasp_inspector.core.models import Finding
from owasp_inspector.core.module import Module, ScanContext
from owasp_inspector.core.registry import register_module
from owasp_inspector.modules._legacy_common import convert_legacy_finding
from owasp_inspector.modules.xss.context import XssContext
from owasp_inspector.modules.xss.payloads import load_xss_payloads
from owasp_inspector.modules.xss.reflected import ReflectedXssScanner


def _param_targets(discovery) -> list[tuple[str, dict]]:
    return [(t.method, {"url": t.url, "params": t.params, "defaults": t.defaults}) for t in discovery.targets]


@register_module
class XssModule(Module):
    """Native async port of the reflected-XSS engine (the most common,
    always-applicable XSS check): standard payload sweep plus a
    context-aware follow-up pass that picks JS-string/event-handler/
    attribute-breakout payloads based on where the injected canary landed.
    Ported faithfully from Logic/vulnerability_scan/xss/scanners/reflected.py
    — the classification logic (confidence/status decision table, context
    detection) is unchanged, only the request I/O is now native async.

    Uses shared discovery (context.discovery.targets) instead of crawling
    independently, and its own AsyncHttpClient with retries disabled — an
    XSS probe response that happens to 5xx should be observed as-is, not
    silently retried into something else.

    Not yet ported: Stored XSS, DOM XSS (static JS source/sink analysis +
    dynamic probing), and CSP-bypass scanning
    (Logic/vulnerability_scan/xss/scanners/{stored,dom,csp,waf}.py) — each a
    substantially larger, more specialized engine than reflected XSS. Still
    available via `owasp-inspector-legacy-menu`.
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
            convert_legacy_finding(v, module=self.name, owasp_category=self.owasp_category, target_url=discovery.final_url)
            for v in vulns
        ]
