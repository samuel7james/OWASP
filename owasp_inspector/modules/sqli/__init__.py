from __future__ import annotations

from owasp_inspector.core.http import AsyncHttpClient
from owasp_inspector.core.models import Finding
from owasp_inspector.core.module import Module, ScanContext
from owasp_inspector.core.registry import register_module
from owasp_inspector.modules._raw_finding import finding_from_raw
from owasp_inspector.modules.sqli.builtin import _COOKIE_DENYLIST, BuiltinSqliScanner
from owasp_inspector.modules.sqli.context import SqliContext
from owasp_inspector.modules.sqli.payloads import load_sqli_payloads


def _cookie_targets(discovery, probe_all: bool) -> list[tuple[str, dict]]:
    """Existing session/tracking cookies as injection candidates, same
    denylist the legacy engine used to skip obvious framework/tracking
    cookies (each one costs a full payload sweep for near-certain zero
    signal otherwise)."""
    targets = []
    for name, value in discovery.cookies.items():
        pl = name.lower()
        if pl == "session":
            continue
        if not probe_all and any(bad in pl for bad in _COOKIE_DENYLIST):
            continue
        if not value:
            continue
        targets.append(("cookie", {"url": discovery.final_url, "params": [name], "defaults": {name: value}}))
    return targets


def _param_targets(discovery) -> list[tuple[str, dict]]:
    return [(t.method, {"url": t.url, "params": t.params, "defaults": t.defaults}) for t in discovery.targets]


@register_module
class SqliModule(Module):
    """Native async SQLi detection module: error-based, UNION
    reflection/column-count, boolean/size-diff heuristics, time-based
    (double-confirmed against a control), and auth-bypass
    (control-verified) checks, each with its own false-positive filter.

    Uses shared discovery (`context.discovery.targets`) instead of
    crawling independently. Uses its own `AsyncHttpClient` with retries
    disabled — the shared client retries on 5xx/429, which would triple
    requests on every error-triggering payload and is exactly the signal
    these checks are looking for, not something to retry past.

    Not covered: a cookie-based blind conditional-error extraction solver
    and SQLMap integration — a DBMS-fingerprinting binary-search password
    extractor and an external-tool wrapper respectively, both narrower
    secondary features rather than the primary detection path implemented
    here.
    """

    name = "sqli"
    owasp_category = "A03:2021-Injection"

    async def run(self, context: ScanContext) -> list[Finding]:
        discovery = context.discovery
        if discovery is None or not discovery.ok:
            return []

        settings = context.settings
        probe_all_cookies = getattr(settings, "scan_sqli_probe_all_cookies", False) if settings else False
        targets = _param_targets(discovery) + _cookie_targets(discovery, probe_all=probe_all_cookies)
        if not targets:
            return []

        max_concurrency = getattr(settings, "scan_sqli_workers", 10) if settings else 10

        async with AsyncHttpClient(max_concurrency=max_concurrency, timeout=15.0, max_retries=0) as http:
            sqli_ctx = SqliContext(http, load_sqli_payloads(), cookie=context.target.cookie)
            scanner = BuiltinSqliScanner(http, sqli_ctx, max_concurrency=max_concurrency)
            vulns, candidates = await scanner.scan(targets)

        findings = [
            finding_from_raw(v, module=self.name, owasp_category=self.owasp_category, target_url=discovery.final_url)
            for v in vulns
        ]
        findings.extend(
            finding_from_raw(c, module=self.name, owasp_category=self.owasp_category, target_url=discovery.final_url)
            for c in candidates
        )
        return findings
